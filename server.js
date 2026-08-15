require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// --- Firebase Admin SDK Setup (Modular API) ---
const { initializeApp, cert } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');

// Load service account key safely
const serviceAccount = require('./serviceAccountKey.json');

// Initialize Firebase App
initializeApp({
    credential: cert(serviceAccount)
});

// Helper function to send FCM push notification with custom icon support
async function sendPushNotification(token, title, body, icon = 'ic_notification', color = '#1A60FF') {
    if (!token) return;

    try {
        const message = {
            token: token,
            notification: {
                title: title,
                body: body,
            },
            android: {
                priority: 'high',
                notification: {
                    icon: icon,             // Must match drawable filename in res/drawable (ic_notification)
                    color: color,            // Accent color matching your app theme (#1A60FF)
                    channelId: 'safecircle_alerts', // Required for Android 8.0+ to prevent default icon fallback
                    defaultSound: true,
                    defaultVibrateTimings: true
                }
            }
        };

        const response = await getMessaging().send(message);
    } catch (err) {
        console.error('❌ Error sending push notification:', err.message);
    }
}

async function triggerCircleAlert(circleId, userId, userName, actionMessage, alertType, category) {
    try {
        const [result] = await db.query(
            `INSERT INTO alerts (circle_id, user_id, user_name, action_message, alert_type, category) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [circleId, userId, userName, actionMessage, alertType, category]
        );

        // Broadcast to all active circle listeners in real time via Socket.IO
        io.to(`circle_${circleId}`).emit('new_alert', {
            id: result.insertId,
            name: userName,
            actionText: actionMessage,
            type: alertType,
            category: category,
            timestamp: Date.now()
        });

    } catch (err) {
        console.error('Error logging alert:', err.message);
    }
}

function generateInviteCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excluded confusing characters like I, O, 1, 0
    let result = '';
    for (let i = 0; i < 6; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `KIN-${result}`;
}

// --- Express Middleware ---
app.use(express.json());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));

// --- 1. MySQL Connection Pool ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test Database Connection on Startup
(async () => {
    try {
        const connection = await db.getConnection();
        console.log('✅ Connected to MySQL database successfully.');
        connection.release();
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
    }
})();

// --- 2. HTTP Server & Socket.IO Setup ---
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || "*",
        methods: ["GET", "POST"]
    }
});

// Socket Authentication Middleware
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization;
    if (!token) {
        return next(); // Proceed as guest or handle strict auth by returning new Error("Unauthorized")
    }

    try {
        const cleanToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(cleanToken, process.env.JWT_SECRET);
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error("Authentication error"));
    }
});

io.on('connection', (socket) => {
    console.log(`⚡ Client connected: ${socket.id}`);

    // Join a specific Circle/Room for real-time tracking
    socket.on('join_circle', (circleId) => {
        if (!circleId) return;
        socket.join(`circle_${circleId}`);
        console.log(`Socket ${socket.id} joined circle_${circleId}`);
    });

    // Leave Circle/Room
    socket.on('leave_circle', (circleId) => {
        if (!circleId) return;
        socket.leave(`circle_${circleId}`);
        console.log(`Socket ${socket.id} left circle_${circleId}`);
    });

    // Broadcast location update to all members in the circle except sender
    socket.on('update_location', (data) => {
        const { circleId, latitude, longitude, userId } = data;
        if (!circleId || !latitude || !longitude) return;

        socket.to(`circle_${circleId}`).emit('member_location_updated', {
            userId: userId || socket.user?.id,
            latitude,
            longitude,
            timestamp: new Date().toISOString()
        });
    });

    socket.on('disconnect', () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
    });
});

// Helper function to calculate distance between two coordinates in meters (Haversine Formula)
function getDistanceInMeters(lat1, lon1, lat2, lon2) {
    if (lat1 == null || lon1 == null || lat2 == null || lon2 == null) return Infinity;
    
    const R = 6371000; // Radius of Earth in meters
    const dLat = (lat2 - lat1) * (Math.PI / 180);
    const dLon = (lon2 - lon1) * (Math.PI / 180);
    const a = 
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1 * (Math.PI / 180)) * Math.cos(lat2 * (Math.PI / 180)) * 
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c; // Distance in meters
}

// --- JWT Verification Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expecting "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: "Access token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, message: "Invalid or expired token" });
        }
        req.user = decoded; // Contains { id, email }
        next();
    });
};

// --- 3. Auth Routes ---
// SIGNUP ENDPOINT
app.post('/api/auth/signup', async (req, res) => {
    // 1. Accept optional fcmToken alongside fullName, email, and password
    const { fullName, email, password, fcmToken } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: "Password must be at least 6 characters long" });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();

        // Check if user exists
        const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [normalizedEmail]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already registered" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Insert new user with fcm_token
        const [result] = await db.query(
            "INSERT INTO users (full_name, email, password, fcm_token) VALUES (?, ?, ?, ?)",
            [fullName.trim(), normalizedEmail, hashedPassword, fcmToken || null]
        );

        // 3. Send Welcome Push Notification if token is available
        if (fcmToken) {
            sendPushNotification(
                fcmToken,
                "Welcome to SafeCircle! 🎉",
                `Hi ${fullName.trim()}, your account has been created successfully.`
            );
        }

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            userId: result.insertId
        });

    } catch (err) {
        console.error('Signup Error:', err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
    // 1. Accept optional fcmToken alongside email and password
    const { email, password, fcmToken } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();
        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [normalizedEmail]);

        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        // 2. Update user's FCM token in MySQL if provided from Android app
        if (fcmToken) {
            await db.query("UPDATE users SET fcm_token = ? WHERE id = ?", [fcmToken, user.id]);
        }

        // 3. Sign JWT Token with explicit expiration (7 days)
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // 4. Send Instant Security Push Notification
        const targetToken = fcmToken || user.fcm_token;
        if (targetToken) {
            sendPushNotification(
                targetToken,
                "New Login Alert 🔒",
                `Your SafeCircle account was just logged in.`
            );
        }

        res.status(200).json({
            success: true,
            message: "Login successful",
            token: token,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email
            }
        });

    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});


// GET PROFILE ENDPOINT (/api/auth/me)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        // 1. Get logged-in user details and their circle
        const [userRows] = await db.query(`
            SELECT u.id, u.full_name, u.email, u.profile_avatar, c.id AS circle_id, c.name AS circle_name, c.invite_code
            FROM users u
            LEFT JOIN circle_members cm ON u.id = cm.user_id
            LEFT JOIN circles c ON cm.circle_id = c.id
            WHERE u.id = ?
            LIMIT 1
        `, [req.user.id]);

        if (userRows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const user = userRows[0];
        let circleData = null;

        // 2. Fetch all circle members with user states, location, and updated_at
        if (user.circle_id) {
            const [memberRows] = await db.query(`
                SELECT 
                    u.id, 
                    u.full_name, 
                    u.email,
                    u.profile_avatar,
                    COALESCE(us.battery_level, 100) AS battery_level,
                    COALESCE(us.speed, '0 km/h') AS speed,
                    COALESCE(us.location, 'Unknown') AS location,
                    us.latitude,
                    us.longitude,
                    us.updated_at,
                    CASE 
                        WHEN us.updated_at IS NULL THEN 'Offline'
                        WHEN TIMESTAMPDIFF(MINUTE, us.updated_at, NOW()) > 5 THEN 'Offline'
                        ELSE COALESCE(us.status, 'Active')
                    END AS current_status
                FROM circle_members cm
                JOIN users u ON cm.user_id = u.id
                LEFT JOIN user_states us ON u.id = us.user_id
                WHERE cm.circle_id = ?
            `, [user.circle_id]);

            circleData = {
                id: user.circle_id,
                name: user.circle_name,
                inviteCode: user.invite_code,
                members: memberRows.map(m => ({
                    id: m.id,
                    fullName: m.full_name,
                    email: m.email,
                    profileAvatar: m.profile_avatar || null,
                    profile_avatar: m.profile_avatar || null,
                    status: m.current_status,
                    batteryLevel: m.battery_level,
                    speed: m.speed,
                    location: m.location,
                    latitude: m.latitude,
                    longitude: m.longitude,
                    updatedAt: m.updated_at ? m.updated_at.toISOString() : null,
                    updated_at: m.updated_at ? m.updated_at.toISOString() : null
                }))
            };
        }

        return res.status(200).json({
            success: true,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email,
                profile_avatar: user.profile_avatar || null,
                profileAvatar: user.profile_avatar || null,
                circle: circleData
            }
        });
    } catch (error) {
        console.error('Fetch Profile Error:', error);
        return res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// --- UPDATE PROFILE AVATAR ROUTE ---
// PUT /api/user/profile/avatar
app.put('/api/user/profile/avatar', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { profile_avatar } = req.body;

        if (!profile_avatar) {
            return res.status(400).json({ success: false, message: "Profile avatar string is required" });
        }

        // Update profile_avatar in users table
        const [result] = await db.query(
            "UPDATE users SET profile_avatar = ? WHERE id = ?",
            [profile_avatar, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        return res.status(200).json({
            success: true,
            message: "Profile avatar updated successfully",
            profile_avatar: profile_avatar
        });
    } catch (error) {
        console.error('Update Avatar Error:', error);
        return res.status(500).json({ success: false, message: "Server error: " + error.message });
    }
});

app.post('/api/auth/fcm-token', authenticateToken, async (req, res) => {
    const { fcmToken } = req.body;
    if (!fcmToken) {
        return res.status(400).json({ success: false, message: "FCM token required" });
    }

    try {
        await db.query("UPDATE users SET fcm_token = ? WHERE id = ?", [fcmToken, req.user.id]);
        res.status(200).json({ success: true, message: "FCM token updated successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/admin/send-notification
app.post('/api/admin/send-notification', async (req, res) => {
    const { targetType, userId, title, message } = req.body;
    // targetType can be 'BROADCAST' or 'SINGLE_USER'

    try {
        if (targetType === 'BROADCAST') {
            // Send to topic 'all_users'
            await getMessaging().send({
                topic: 'all_users',
                notification: { title, body: message }
            });
            return res.json({ success: true, message: "Broadcast sent to all users" });

        } else if (targetType === 'SINGLE_USER') {
            // Fetch target user's FCM token from DB
            const [rows] = await db.query("SELECT fcm_token FROM users WHERE id = ?", [userId]);
            if (rows.length === 0 || !rows[0].fcm_token) {
                return res.status(404).json({ success: false, message: "User FCM token not found" });
            }

            await sendPushNotification(rows[0].fcm_token, title, message);
            return res.json({ success: true, message: `Notification sent to user ID ${userId}` });
        }

        res.status(400).json({ success: false, message: "Invalid targetType" });

    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/circle/create', async (req, res) => {
    const { userId, circleName } = req.body;

    if (!userId || !circleName) {
        return res.status(400).json({ success: false, message: 'User ID and Circle Name are required' });
    }

    const inviteCode = generateInviteCode();

    try {
        // Insert into circles table
        const [circleResult] = await db.execute(
            'INSERT INTO circles (name, invite_code, created_by) VALUES (?, ?, ?)',
            [circleName, inviteCode, userId]
        );

        const circleId = circleResult.insertId;

        // Add creator into circle_members table as admin
        await db.execute(
            'INSERT INTO circle_members (circle_id, user_id, role) VALUES (?, ?, ?)',
            [circleId, userId, 'admin']
        );

        res.status(200).json({
            success: true,
            message: 'Circle created successfully',
            circle: {
                id: circleId,
                name: circleName,
                inviteCode: inviteCode
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Failed to create circle' });
    }
});

app.post('/api/circle/join', async (req, res) => {
    const { userId, inviteCode } = req.body;

    if (!userId || !inviteCode) {
        return res.status(400).json({ success: false, message: 'User ID and Invite Code are required' });
    }

    try {
        // Find circle by invite code
        const [circles] = await db.execute(
            'SELECT id, name, invite_code FROM circles WHERE invite_code = ?',
            [inviteCode.trim().toUpperCase()]
        );

        if (circles.length === 0) {
            return res.status(404).json({ success: false, message: 'Invalid Invite Code. Circle not found.' });
        }

        const circle = circles[0];

        // Check if user is already a member
        const [existing] = await db.execute(
            'SELECT id FROM circle_members WHERE circle_id = ? AND user_id = ?',
            [circle.id, userId]
        );

        if (existing.length > 0) {
            return res.status(200).json({
                success: true,
                message: 'You are already a member of this circle',
                circle: circle
            });
        }

        // Add user to circle_members
        await db.execute(
            'INSERT INTO circle_members (circle_id, user_id, role) VALUES (?, ?, ?)',
            [circle.id, userId, 'member']
        );

        res.status(200).json({
            success: true,
            message: 'Successfully joined circle',
            circle: circle
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Failed to join circle' });
    }
});

// PUT /api/user/state - Update current user's battery, status, speed, and location
app.put('/api/user/state', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { batteryLevel, status, speed, latitude, longitude, lat, lng } = req.body;

        // Support both naming conventions
        const finalLat = latitude !== undefined ? latitude : (lat !== undefined ? lat : null);
        const finalLng = longitude !== undefined ? longitude : (lng !== undefined ? lng : null);

        let locationName = "Unknown";

        // 1. Fetch user's circle ID
        const [circleRows] = await db.query(
            "SELECT circle_id FROM circle_members WHERE user_id = ? LIMIT 1",
            [userId]
        );

        if (circleRows.length > 0 && finalLat !== null && finalLng !== null) {
            const circleId = circleRows[0].circle_id;

            // 2. Fetch all registered places for this circle
            const [places] = await db.query(
                "SELECT name, latitude, longitude, safe_zone_radius_meters FROM places WHERE circle_id = ?",
                [circleId]
            );

            // 3. Match user coordinates with places using safe_zone_radius_meters
            for (const place of places) {
                const distance = getDistanceInMeters(
                    parseFloat(finalLat),
                    parseFloat(finalLng),
                    parseFloat(place.latitude),
                    parseFloat(place.longitude)
                );

                const radius = place.safe_zone_radius_meters || 200; // Default to 200m if radius not set

                if (distance <= radius) {
                    locationName = place.name;
                    break;
                }
            }
        }

        // 4. Upsert user state including matched location and timestamp
        const query = `
            INSERT INTO user_states (user_id, battery_level, status, speed, latitude, longitude, location, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE 
                battery_level = VALUES(battery_level),
                status = VALUES(status),
                speed = VALUES(speed),
                latitude = VALUES(latitude),
                longitude = VALUES(longitude),
                location = VALUES(location),
                updated_at = NOW()
        `;

        await db.query(query, [
            userId,
            batteryLevel || 100,
            status || 'Active',
            speed || '0 km/h',
            finalLat,
            finalLng,
            locationName
        ]);

        // 5. Broadcast real-time location & state update via Socket.IO
        if (circleRows.length > 0) {
            const circleId = circleRows[0].circle_id;
            io.to(`circle_${circleId}`).emit('member_location_updated', {
                userId: userId,
                latitude: finalLat,
                longitude: finalLng,
                batteryLevel: batteryLevel || 100,
                status: status || 'Active',
                speed: speed || '0 km/h',
                location: locationName,
                updatedAt: new Date().toISOString()
            });
        }

        return res.status(200).json({ 
            success: true, 
            message: "State and location updated successfully",
            location: locationName 
        });

    } catch (error) {
        console.error('Update State Error:', error);
        return res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// --- UPDATED PLACES API ROUTES ---

/**
 * POST /api/places/add
 * Protected Route: Adds/Updates a place for the user's active Circle
 */
app.post('/api/places/add', authenticateToken, async (req, res) => {
    const { id, name, address, safeZoneRadiusMeters, iconResId, latitude, longitude, circleId: bodyCircleId } = req.body;
    const userId = req.user.id;

    if (!id || !name || latitude == null || longitude == null) {
        return res.status(400).json({
            success: false,
            message: "Missing required fields: id, name, latitude, or longitude"
        });
    }

    try {
        let activeCircleId = bodyCircleId;

        // If circleId is not passed in body, fetch user's active circle_id from DB
        if (!activeCircleId) {
            const [circleRows] = await db.query(
                "SELECT circle_id FROM circle_members WHERE user_id = ? LIMIT 1",
                [userId]
            );

            if (circleRows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "You must join or create a Circle before adding places."
                });
            }
            activeCircleId = circleRows[0].circle_id;
        }

        const query = `
            INSERT INTO places (id, circle_id, created_by_user_id, name, address, safe_zone_radius_meters, icon_res_id, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                name = VALUES(name),
                address = VALUES(address),
                safe_zone_radius_meters = VALUES(safe_zone_radius_meters),
                icon_res_id = VALUES(icon_res_id),
                latitude = VALUES(latitude),
                longitude = VALUES(longitude)
        `;

        await db.execute(query, [
            id,
            activeCircleId,
            userId,
            name,
            address || 'Custom Address',
            safeZoneRadiusMeters || 200,
            iconResId || 0,
            latitude,
            longitude
        ]);

        // Optional Socket.IO Real-Time Broadcast to all members in this Circle
        io.to(`circle_${activeCircleId}`).emit('place_added', {
            id,
            name,
            address,
            safeZoneRadiusMeters,
            iconResId,
            latitude,
            longitude,
            createdBy: userId
        });

        return res.status(201).json({
            success: true,
            message: "Place added to circle successfully",
            placeId: id,
            circleId: activeCircleId
        });

    } catch (error) {
        console.error('Add Place Error:', error);
        return res.status(500).json({
            success: false,
            message: "Server error: " + error.message
        });
    }
});
/**
 * GET /api/places
 * Protected Route: Fetches all places shared within the authenticated user's Circle
 */
app.get('/api/places', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // 1. Get the Circle ID of the user
        const [userCircle] = await db.query(
            "SELECT circle_id FROM circle_members WHERE user_id = ? LIMIT 1",
            [userId]
        );

        if (userCircle.length === 0) {
            return res.status(200).json({
                success: true,
                places: []
            });
        }

        const circleId = userCircle[0].circle_id;

        // 2. Query all places associated with this circle
        const [rows] = await db.query(
            `SELECT 
                p.id, 
                p.name, 
                p.address, 
                p.safe_zone_radius_meters AS safeZoneRadiusMeters, 
                p.icon_res_id AS iconResId, 
                p.latitude, 
                p.longitude,
                p.created_by_user_id AS createdBy
            FROM places p
            WHERE p.circle_id = ? 
            ORDER BY p.created_at DESC`,
            [circleId]
        );

        return res.status(200).json({
            success: true,
            circleId: circleId,
            places: rows
        });

    } catch (error) {
        console.error('Get Places Error:', error);
        return res.status(500).json({
            success: false,
            message: "Server error: " + error.message
        });
    }
});

/**
 * GET /api/alerts
 * Protected Route: Returns shared circle alerts formatted for Android AlertsAdapter
 */
app.get('/api/alerts', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // 1. Get current user's circle
        const [circleRows] = await db.query(
            "SELECT circle_id FROM circle_members WHERE user_id = ? LIMIT 1",
            [userId]
        );

        if (circleRows.length === 0) {
            return res.status(200).json({
                success: true,
                alerts: []
            });
        }

        const circleId = circleRows[0].circle_id;

        // 2. Dynamic check: Generate system low-battery alerts from user_states
        const [lowBatteryStates] = await db.query(
            `SELECT us.user_id, u.full_name, us.battery_level 
             FROM user_states us
             JOIN circle_members cm ON us.user_id = cm.user_id
             JOIN users u ON us.user_id = u.id
             WHERE cm.circle_id = ? AND us.battery_level <= 20`,
            [circleId]
        );

        for (const state of lowBatteryStates) {
            const actionMsg = `Battery critical (${state.battery_level}%)`;

            // Check if alert already logged recently to prevent duplicate spam
            const [recent] = await db.query(
                `SELECT id FROM alerts 
                 WHERE circle_id = ? AND user_id = ? AND alert_type = 'BATTERY' 
                 AND created_at >= NOW() - INTERVAL 1 HOUR`,
                [circleId, state.user_id]
            );

            if (recent.length === 0) {
                await db.query(
                    `INSERT INTO alerts (circle_id, user_id, user_name, action_message, alert_type, category) 
                     VALUES (?, ?, ?, ?, 'BATTERY', 'System')`,
                    [circleId, state.user_id, state.full_name, actionMsg]
                );
            }
        }

        // 3. Fetch all alerts for the circle sorted by newest first
        const [alertRows] = await db.query(
            `SELECT 
                id,
                user_name AS name,
                action_message AS actionText,
                alert_type AS type,
                category,
                UNIX_TIMESTAMP(created_at) * 1000 AS timestamp
            FROM alerts 
            WHERE circle_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50`,
            [circleId]
        );

        // Map data keys to align directly with Android AlertModel.fromJson()
        const formattedAlerts = alertRows.map(alert => ({
            id: alert.id,
            name: alert.name,
            actionText: alert.actionText,
            type: alert.type,
            category: alert.category,
            timestamp: alert.timestamp
        }));

        return res.status(200).json({
            success: true,
            circleId: circleId,
            alerts: formattedAlerts
        });

    } catch (error) {
        console.error('Fetch Alerts Error:', error);
        return res.status(500).json({
            success: false,
            message: "Server error: " + error.message
        });
    }
});

// --- Server Startup ---
const PORT = process.env.PORT || 5100;
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
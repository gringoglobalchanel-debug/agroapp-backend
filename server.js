const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY, { timeout: 30000, maxNetworkRetries: 3 });
require("dotenv").config();

const app = express();

app.use((req, res, next) => {
    console.log(`📍 [${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.get("/", (req, res) => {
    res.json({ message: "🌱 API de AgroApp funcionando correctamente", version: "2.0.0", status: "online" });
});

app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString(), uptime: process.uptime() });
});

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
    console.error("❌ ERROR: Variables de entorno faltantes");
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);
console.log("✅ Supabase conectado");

async function getFcmAccessToken() {
    const { GoogleAuth } = require('google-auth-library');
    const auth = new GoogleAuth({
        credentials: {
            type: 'service_account',
            project_id: process.env.FIREBASE_PROJECT_ID,
            private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
            client_email: process.env.FIREBASE_CLIENT_EMAIL,
        },
        scopes: ['https://www.googleapis.com/auth/firebase.messaging'],
    });
    const client = await auth.getClient();
    const token = await client.getAccessToken();
    return token.token;
}

async function sendPushNotification(fcmToken, title, body) {
    try {
        const accessToken = await getFcmAccessToken();
        const projectId = process.env.FIREBASE_PROJECT_ID;
        const response = await fetch(`https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: { token: fcmToken, notification: { title, body }, android: { priority: 'high' } } })
        });
        const result = await response.json();
        if (!response.ok) console.error('❌ FCM error:', JSON.stringify(result));
        else console.log('✅ Notificacion enviada');
    } catch (e) { console.error('❌ Error enviando notificacion:', e.message); }
}

function getDavidZone(lat, lng) {
    if (!lat || !lng) return 'centro';
    if (lat > 8.440) return 'norte';
    if (lat < 8.415) return 'sur';
    return 'centro';
}

function getDeliveryWindow(orderTime) {
    const panamaOffset = -5 * 60;
    const utcMinutes = orderTime.getUTCHours() * 60 + orderTime.getUTCMinutes();
    const panamaMinutes = ((utcMinutes + panamaOffset) + 24 * 60) % (24 * 60);
    const panamaHour = Math.floor(panamaMinutes / 60);
    const today = new Date(orderTime);
    today.setUTCMinutes(today.getUTCMinutes() + panamaOffset);
    const todayDate = today.toISOString().split('T')[0];
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowDate = tomorrow.toISOString().split('T')[0];
    if (panamaHour >= 8 && panamaHour < 12) return { date: todayDate, start: '14:00', end: '17:00', label: 'hoy entre 2:00pm y 5:00pm' };
    if (panamaHour >= 14 && panamaHour < 18) return { date: tomorrowDate, start: '09:00', end: '12:00', label: 'manana entre 9:00am y 12:00pm' };
    return { date: tomorrowDate, start: '09:00', end: '12:00', label: 'manana entre 9:00am y 12:00pm' };
}

async function agruparPedidosPorZona() {
    console.log(`🔄 [${new Date().toISOString()}] Iniciando agrupacion de pedidos por zona...`);
    try {
        const now = new Date();
        const panamaOffset = -5 * 60;
        const panamaMs = now.getTime() + panamaOffset * 60 * 1000;
        const panamaDate = new Date(panamaMs);
        const panamaHour = panamaDate.getUTCHours();
        let targetDate, targetStart, targetEnd;
        if (panamaHour === 12) { targetDate = panamaDate.toISOString().split('T')[0]; targetStart = '14:00'; targetEnd = '17:00'; }
        else if (panamaHour === 18) { const tomorrow = new Date(panamaDate); tomorrow.setDate(tomorrow.getDate() + 1); targetDate = tomorrow.toISOString().split('T')[0]; targetStart = '09:00'; targetEnd = '12:00'; }
        else { console.log('⏰ No es hora de corte, saltando agrupacion'); return; }
        const { data: pedidos, error } = await supabase.from('orders').select('id, zone, delivery_window_date, delivery_window_start').eq('status', 'pending').eq('payment_status', 'completed').eq('delivery_window_date', targetDate).eq('delivery_window_start', targetStart).is('dynamic_package_id', null);
        if (error) { console.error('❌ Error obteniendo pedidos:', error.message); return; }
        if (!pedidos || pedidos.length === 0) { console.log('📭 No hay pedidos para agrupar'); return; }
        const porZona = { norte: [], centro: [], sur: [] };
        for (const p of pedidos) { const zona = p.zone || 'centro'; if (!porZona[zona]) porZona[zona] = []; porZona[zona].push(p.id); }
        for (const [zona, ids] of Object.entries(porZona)) {
            if (ids.length === 0) continue;
            const bloques = [];
            for (let i = 0; i < ids.length; i += 8) bloques.push(ids.slice(i, i + 8));
            for (const bloque of bloques) {
                const { data: pkg, error: pkgError } = await supabase.from('dynamic_packages').insert({ current_size: bloque.length, max_size: 8, status: 'available', zone: zona, delivery_date: targetDate, delivery_window_start: targetStart, delivery_window_end: targetEnd, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }).select().single();
                if (pkgError) { console.error(`❌ Error creando paquete zona ${zona}:`, pkgError.message); continue; }
                await supabase.from('package_orders').insert(bloque.map(orderId => ({ package_id: pkg.id, order_id: orderId })));
                await supabase.from('orders').update({ dynamic_package_id: pkg.id }).in('id', bloque);
                console.log(`✅ Paquete zona ${zona} creado con ${bloque.length} pedidos`);
            }
        }
        console.log('✅ Agrupacion completada');
    } catch (e) { console.error('❌ Error en agrupacion:', e.message); }
}

setInterval(async () => {
    const now = new Date();
    const panamaOffset = -5 * 60;
    const panamaMs = now.getTime() + panamaOffset * 60 * 1000;
    const panamaDate = new Date(panamaMs);
    const panamaHour = panamaDate.getUTCHours();
    const panamaMin = panamaDate.getUTCMinutes();
    if ((panamaHour === 12 || panamaHour === 18) && panamaMin === 0) await agruparPedidosPorZona();
}, 60 * 1000);

const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });
    try { const decoded = jwt.verify(token, JWT_SECRET); req.user = decoded; next(); }
    catch { res.status(401).json({ error: "Token invalido" }); }
};

const driverMiddleware = async (req, res, next) => {
    const { data: user, error } = await supabase.from("users").select("user_type").eq("id", req.user.userId).single();
    if (error || user.user_type !== "driver") return res.status(403).json({ error: "No autorizado. Solo repartidores." });
    next();
};

const adminMiddleware = async (req, res, next) => {
    const { data: user, error } = await supabase.from("users").select("role").eq("id", req.user.userId).single();
    if (error || user.role !== "admin") return res.status(403).json({ error: "No autorizado. Solo administradores." });
    next();
};

// ==================== REGISTRO DRIVER CON CODIGO ====================

app.post("/auth/register/driver", async (req, res) => {
    const { full_name, email, password, phone, address, invite_code } = req.body;
    if (!full_name || !email || !password) return res.status(400).json({ error: "Faltan campos: nombre, email y contrasena son requeridos" });
    if (!invite_code || invite_code !== process.env.DRIVER_INVITE_CODE) {
        return res.status(403).json({ error: "Codigo de invitacion invalido" });
    }
    try {
        const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
        if (existing) return res.status(400).json({ error: "Email ya registrado" });
        const hashed = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert({
            full_name, email, password_hash: hashed, phone: phone || null, address: address || null,
            role: "cliente", user_type: "driver"
        }).select().single();
        if (error) throw error;
        console.log(`✅ Nuevo driver registrado: ${email}`);
        res.json({ message: "Cuenta de repartidor creada", userId: data.id });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== AUTH ====================

app.post("/auth/register", async (req, res) => {
    const { full_name: name, email, password, phone, address, user_type } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Faltan campos: nombre, email y contrasena son requeridos" });
    if (password.length < 6) return res.status(400).json({ error: "La contrasena debe tener al menos 6 caracteres" });
    const userType = user_type === "driver" ? "driver" : "cliente";
    try {
        const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
        if (existing) return res.status(400).json({ error: "Email ya registrado" });
        const hashed = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert({
            full_name: name, email, password_hash: hashed,
            phone: phone || null, address: address || null,
            role: "cliente", user_type: userType
        }).select().single();
        if (error) throw error;
        console.log(`✅ Nuevo usuario registrado: ${email}`);
        res.json({ message: "Usuario creado", userId: data.id });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: user, error } = await supabase.from("users").select("*").eq("email", email).single();
        if (error || !user) return res.status(401).json({ error: "Credenciales invalidas" });
        let valid = false;
        if (password === user.password_hash) { valid = true; }
        else { try { valid = await bcrypt.compare(password, user.password_hash); } catch (e) {} }
        if (!valid) return res.status(401).json({ error: "Credenciales invalidas" });
        const token = jwt.sign({ userId: user.id, role: user.role, userType: user.user_type || "cliente", name: user.full_name, address: user.address }, JWT_SECRET, { expiresIn: "7d" });
        res.json({ token, userId: user.id, name: user.full_name, role: user.role, address: user.address, user_type: user.user_type || "cliente", avatar_url: user.avatar_url || null });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/auth/profile", authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("id, full_name, email, phone, address, role, user_type, avatar_url").eq("id", req.user.userId).single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/auth/profile", authMiddleware, async (req, res) => {
    const { full_name, phone, address } = req.body;
    try {
        const { data, error } = await supabase.from("users").update({ full_name, phone, address }).eq("id", req.user.userId).select().single();
        if (error) throw error;
        res.json({ message: "Perfil actualizado", name: data.full_name, phone: data.phone, address: data.address });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/auth/password", authMiddleware, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Faltan campos" });
    if (newPassword.length < 6) return res.status(400).json({ error: "La contrasena debe tener al menos 6 caracteres" });
    try {
        const { data: user, error } = await supabase.from("users").select("*").eq("id", req.user.userId).single();
        if (error || !user) return res.status(404).json({ error: "Usuario no encontrado" });
        const valid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!valid) return res.status(401).json({ error: "Contrasena actual incorrecta" });
        const hashed = await bcrypt.hash(newPassword, 10);
        const { error: updateError } = await supabase.from("users").update({ password_hash: hashed }).eq("id", req.user.userId);
        if (updateError) throw updateError;
        res.json({ message: "Contrasena actualizada correctamente" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/auth/avatar", authMiddleware, async (req, res) => {
    const { imageBase64, mimeType } = req.body;
    if (!imageBase64) return res.status(400).json({ error: "imageBase64 es requerido" });
    try {
        const userId = req.user.userId;
        const fileName = `avatar_${userId}_${Date.now()}.jpg`;
        const fileBuffer = Buffer.from(imageBase64, 'base64');
        const contentType = mimeType || 'image/jpeg';
        const { error: uploadError } = await supabase.storage.from('avatars').upload(fileName, fileBuffer, { contentType, upsert: true });
        if (uploadError) { console.error('❌ Error subiendo imagen:', JSON.stringify(uploadError)); throw uploadError; }
        const { data: urlData } = supabase.storage.from('avatars').getPublicUrl(fileName);
        const avatarUrl = urlData.publicUrl;
        const { error: updateError } = await supabase.from('users').update({ avatar_url: avatarUrl }).eq('id', userId);
        if (updateError) throw updateError;
        res.json({ success: true, avatar_url: avatarUrl });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/users/:userId/avatar", authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("avatar_url, full_name").eq("id", req.params.userId).single();
        if (error) throw error;
        res.json({ avatar_url: data.avatar_url || null, full_name: data.full_name });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/auth/fcm-token", authMiddleware, async (req, res) => {
    const { fcm_token } = req.body;
    if (!fcm_token) return res.status(400).json({ error: "fcm_token es requerido" });
    try {
        const { error } = await supabase.from("users").update({ fcm_token }).eq("id", req.user.userId);
        if (error) throw error;
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== PRODUCTOS ====================

app.get("/products", async (req, res) => {
    try {
        const { data, error } = await supabase.from("products").select("*, categories(name)").eq("is_available", true).order("category_id");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== PEDIDOS ====================

app.post("/orders", authMiddleware, async (req, res) => {
    const { items, paymentMethod, payment_method, deliveryAddress, delivery_address, delivery_latitude, delivery_longitude, notes, tip_amount } = req.body;
    const finalPaymentMethod = paymentMethod || payment_method;
    const finalDeliveryAddress = deliveryAddress || delivery_address;
    const finalTipAmount = parseFloat(tip_amount) || 0;
    const finalLatitude = delivery_latitude || null;
    const finalLongitude = delivery_longitude || null;
    if (!items || items.length === 0) return res.status(400).json({ error: "Carrito vacio" });
    if (!finalPaymentMethod) return res.status(400).json({ error: "payment_method es requerido" });
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product, error: productError } = await supabase.from("products").select("stock, name").eq("id", productId).single();
        if (productError || !product) return res.status(400).json({ error: `Producto no encontrado: ID ${productId}` });
        if (product.stock < item.quantity) return res.status(400).json({ error: `Stock insuficiente para ${product.name}.` });
    }
    const zone = getDavidZone(finalLatitude, finalLongitude);
    const window = getDeliveryWindow(new Date());
    let totalAmount = 0;
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product } = await supabase.from("products").select("price").eq("id", productId).single();
        if (product) totalAmount += parseFloat(product.price) * parseFloat(item.quantity);
    }
    totalAmount += finalTipAmount;
    totalAmount = parseFloat(totalAmount.toFixed(2));
    try {
        const { data: order, error: orderError } = await supabase.from("orders").insert({ user_id: req.user.userId, payment_method: finalPaymentMethod, payment_status: "completed", delivery_address: finalDeliveryAddress || req.user.address, delivery_latitude: finalLatitude, delivery_longitude: finalLongitude, delivery_date: window.date, total_amount: totalAmount, tip_amount: finalTipAmount, notes: notes || null, status: "pending", zone: zone, delivery_window_start: window.start, delivery_window_end: window.end, delivery_window_date: window.date }).select().single();
        if (orderError) throw orderError;
        const productPrices = {};
        for (const item of items) {
            const productId = item.productId || item.product_id;
            const { data: product } = await supabase.from("products").select("price").eq("id", productId).single();
            if (product) productPrices[productId] = product.price;
        }
        const orderItems = items.map(item => ({ order_id: order.id, product_id: item.productId || item.product_id, quantity: item.quantity, unit_price: productPrices[item.productId || item.product_id] || 0 }));
        const { error: itemsError } = await supabase.from("order_items").insert(orderItems);
        if (itemsError) throw itemsError;
        for (const item of items) {
            const productId = item.productId || item.product_id;
            const { data: product } = await supabase.from("products").select("stock").eq("id", productId).single();
            const previousStock = product.stock;
            const newStock = previousStock - item.quantity;
            await supabase.from("products").update({ stock: newStock }).eq("id", productId);
            await supabase.from("inventory_logs").insert({ product_id: productId, previous_quantity: previousStock, new_quantity: newStock, change_type: "sale", order_id: order.id, notes: `Venta en pedido ${order.id}`, created_by: req.user.userId });
        }
        res.json({ message: "Pedido creado", orderId: order.id, deliveryDate: window.date, deliveryWindow: window.label, zone });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/orders/my", authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("orders").select("*, order_items(*, products(name, unit))").eq("user_id", req.user.userId).order("created_at", { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/orders/active", authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("orders").select("id, status, total_amount, driver_id, delivery_latitude, delivery_longitude").eq("user_id", req.user.userId).in("status", ["pending", "in_progress"]).eq("payment_status", "completed").order("created_at", { ascending: false }).limit(1).single();
        if (error && error.code === "PGRST116") return res.json(null);
        if (error) throw error;
        res.json({ id: data.id, status: data.status, total: data.total_amount, driver_id: data.driver_id || null, delivery_lat: data.delivery_latitude || null, delivery_lng: data.delivery_longitude || null });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/orders/:id/cancel", authMiddleware, async (req, res) => {
    try {
        const { data: order, error: fetchError } = await supabase.from("orders").select("*").eq("id", req.params.id).single();
        if (fetchError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId) return res.status(403).json({ error: "No autorizado" });
        if (order.status !== "pending" && order.status !== "waiting_confirmation") return res.status(400).json({ error: "Solo se pueden cancelar pedidos pendientes" });
        const { data: orderItems } = await supabase.from("order_items").select("product_id, quantity").eq("order_id", order.id);
        for (const item of orderItems || []) {
            const { data: product } = await supabase.from("products").select("stock").eq("id", item.product_id).single();
            await supabase.from("products").update({ stock: product.stock + item.quantity }).eq("id", item.product_id);
        }
        const { data, error } = await supabase.from("orders").update({ status: "cancelled" }).eq("id", req.params.id).select().single();
        if (error) throw error;
        res.json({ message: "Pedido cancelado", order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== YAPPI ====================

function generateReferenceCode() {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `${year}${month}${day}-${random}`;
}

app.post("/orders/pending-yappi", authMiddleware, async (req, res) => {
    const { items, deliveryAddress, delivery_address, delivery_latitude, delivery_longitude, tip_amount } = req.body;
    const finalDeliveryAddress = deliveryAddress || delivery_address;
    const finalTipAmount = parseFloat(tip_amount) || 0;
    if (!items || items.length === 0) return res.status(400).json({ error: "Carrito vacio" });
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product } = await supabase.from("products").select("stock, name").eq("id", productId).single();
        if (!product) return res.status(400).json({ error: `Producto no encontrado: ID ${productId}` });
        if (product.stock < item.quantity) return res.status(400).json({ error: `Stock insuficiente` });
    }
    const referenceCode = generateReferenceCode();
    const zone = getDavidZone(delivery_latitude, delivery_longitude);
    const window = getDeliveryWindow(new Date());
    let totalAmount = 0;
    const productPrices = {};
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product } = await supabase.from("products").select("price").eq("id", productId).single();
        if (product) { productPrices[productId] = product.price; totalAmount += parseFloat(product.price) * parseFloat(item.quantity); }
    }
    totalAmount += finalTipAmount;
    totalAmount = parseFloat(totalAmount.toFixed(2));
    try {
        const { data: order, error: orderError } = await supabase.from("orders").insert({ user_id: req.user.userId, payment_method: "yappi", payment_status: "pending", delivery_address: finalDeliveryAddress || req.user.address, delivery_latitude: delivery_latitude || null, delivery_longitude: delivery_longitude || null, delivery_date: window.date, total_amount: totalAmount, tip_amount: finalTipAmount, reference_code: referenceCode, status: "waiting_confirmation", zone: zone, delivery_window_start: window.start, delivery_window_end: window.end, delivery_window_date: window.date }).select().single();
        if (orderError) throw orderError;
        const orderItems = items.map(item => ({ order_id: order.id, product_id: item.productId || item.product_id, quantity: item.quantity, unit_price: productPrices[item.productId || item.product_id] || 0 }));
        const { error: itemsError } = await supabase.from("order_items").insert(orderItems);
        if (itemsError) throw itemsError;
        res.json({ orderId: order.id, referenceCode, totalAmount, deliveryDate: window.date, deliveryWindow: window.label, zone });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/orders/:id/confirm-yappi", authMiddleware, async (req, res) => {
    try {
        const { data: order, error } = await supabase.from("orders").select("*").eq("id", req.params.id).single();
        if (error || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId) return res.status(403).json({ error: "No autorizado" });
        if (order.payment_status === "pending_approval" || order.payment_status === "completed") return res.json({ success: true, message: "Pedido ya enviado a revision" });
        await supabase.from("orders").update({ payment_status: "pending_approval", status: "pending_approval", payment_confirmed_at: new Date().toISOString() }).eq("id", order.id);
        res.json({ success: true, message: "Pago enviado a revision.", orderId: order.id });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN - YAPPI ====================

app.get("/admin/yappi/pending", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("orders").select("id, total_amount, tip_amount, reference_code, created_at, payment_confirmed_at, delivery_address, status, zone, delivery_window_start, delivery_window_end, delivery_window_date, users!orders_user_id_fkey(full_name, phone, email)").eq("payment_method", "yappi").in("status", ["waiting_confirmation", "pending_approval"]).order("created_at", { ascending: false });
        if (error) throw error;
        res.json(data.map(o => ({ id: o.id, total_amount: o.total_amount, tip_amount: o.tip_amount || 0, reference_code: o.reference_code, created_at: o.created_at, payment_confirmed_at: o.payment_confirmed_at, delivery_address: o.delivery_address, status: o.status, zone: o.zone, delivery_window: o.delivery_window_date ? `${o.delivery_window_date} ${o.delivery_window_start}-${o.delivery_window_end}` : null, customer_name: o.users?.full_name || "Cliente", customer_phone: o.users?.phone || "", customer_email: o.users?.email || "" })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/yappi/:orderId/approve", authMiddleware, adminMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data, error } = await supabase.from("orders").update({ payment_status: "completed", status: "pending", updated_at: new Date().toISOString() }).eq("id", orderId).select().single();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "Pedido no encontrado" });
        res.json({ success: true, message: "Pago YAPPI aprobado", order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/yappi/:orderId/reject", authMiddleware, adminMiddleware, async (req, res) => {
    const { orderId } = req.params;
    const { reason } = req.body;
    try {
        const { data: existingOrder, error: fetchError } = await supabase.from("orders").select("id, status, payment_status").eq("id", orderId).single();
        if (fetchError || !existingOrder) return res.status(404).json({ error: "Pedido no encontrado" });
        const { data: orderItems } = await supabase.from("order_items").select("product_id, quantity").eq("order_id", orderId);
        for (const item of orderItems || []) {
            const { data: product } = await supabase.from("products").select("stock").eq("id", item.product_id).single();
            if (product) await supabase.from("products").update({ stock: product.stock + item.quantity }).eq("id", item.product_id);
        }
        const rejectNote = reason ? `Pago rechazado: ${reason}` : "Pago YAPPI rechazado por administrador";
        const { data, error } = await supabase.from("orders").update({ payment_status: "rejected", status: "cancelled", notes: rejectNote, updated_at: new Date().toISOString() }).eq("id", orderId).select();
        if (error) throw error;
        res.json({ success: true, message: "Pago rechazado y stock devuelto", rejectedNote: rejectNote });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN MANUAL AGRUPACION ====================

app.post("/admin/agrupar-pedidos", authMiddleware, adminMiddleware, async (req, res) => {
    try { await agruparPedidosPorZona(); res.json({ success: true, message: "Agrupacion ejecutada manualmente" }); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN - ASIGNACION MANUAL A DRIVER ====================

app.post("/admin/orders/:orderId/assign-driver", authMiddleware, adminMiddleware, async (req, res) => {
    const { orderId } = req.params;
    const { driver_id } = req.body;
    if (!driver_id) return res.status(400).json({ error: "driver_id es requerido" });
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("id, status, payment_status, zone, delivery_window_start, delivery_window_end, delivery_window_date, delivery_date, dynamic_package_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.payment_status !== "completed") return res.status(400).json({ error: "El pedido no tiene pago completado" });
        if (order.dynamic_package_id) return res.status(400).json({ error: "El pedido ya esta asignado a un paquete" });
        const { data: driver, error: driverError } = await supabase.from("users").select("id, full_name, user_type").eq("id", driver_id).single();
        if (driverError || !driver || driver.user_type !== "driver") return res.status(404).json({ error: "Driver no encontrado" });
        const { data: pkg, error: pkgError } = await supabase.from("dynamic_packages").insert({ current_size: 1, max_size: 8, status: "taken", zone: order.zone || "centro", delivery_date: order.delivery_date, delivery_window_start: order.delivery_window_start, delivery_window_end: order.delivery_window_end, taken_by: driver_id, taken_at: new Date().toISOString(), created_at: new Date().toISOString(), updated_at: new Date().toISOString() }).select().single();
        if (pkgError) throw pkgError;
        await supabase.from("package_orders").insert({ package_id: pkg.id, order_id: orderId });
        await supabase.from("orders").update({ dynamic_package_id: pkg.id, driver_id: driver_id, updated_at: new Date().toISOString() }).eq("id", orderId);
        res.json({ success: true, message: `Pedido asignado a ${driver.full_name}`, packageId: pkg.id });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== VENDEDOR ====================

app.get("/vendor/orders/by-client", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    try {
        const { data, error } = await supabase.from("orders_by_client").select("*").eq("delivery_date", date);
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/vendor/orders/by-product", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    try {
        const { data, error } = await supabase.from("orders_by_product").select("*").eq("delivery_date", date);
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/vendor/orders/:id/status", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const { status } = req.body;
    try {
        const { data, error } = await supabase.from("orders").update({ status }).eq("id", req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DRIVER - PAQUETES ====================

app.get("/driver/packages/available", authMiddleware, driverMiddleware, async (req, res) => {
    try {
        const { data: packages, error } = await supabase.from("dynamic_packages").select("id, current_size, max_size, status, zone, delivery_date, delivery_window_start, delivery_window_end, created_at, updated_at").eq("status", "available").order("created_at");
        if (error) throw error;
        const formattedPackages = await Promise.all(packages.map(async (pkg) => {
            const { data: pkgOrders } = await supabase.from("package_orders").select("order_id, orders(id, user_id, delivery_address, delivery_latitude, delivery_longitude, total_amount, tip_amount, payment_method, created_at, zone, delivery_window_start, delivery_window_end, delivery_window_date, users!orders_user_id_fkey(full_name, phone))").eq("package_id", pkg.id);
            return { ...pkg, orders: pkgOrders?.map(po => ({ order_id: po.orders?.id, user_id: po.orders?.user_id, delivery_address: po.orders?.delivery_address, delivery_latitude: po.orders?.delivery_latitude, delivery_longitude: po.orders?.delivery_longitude, total_amount: po.orders?.total_amount, tip_amount: po.orders?.tip_amount || 0, payment_method: po.orders?.payment_method, created_at: po.orders?.created_at, zone: po.orders?.zone, delivery_window_start: po.orders?.delivery_window_start, delivery_window_end: po.orders?.delivery_window_end, delivery_window_date: po.orders?.delivery_window_date, customer_name: po.orders?.users?.full_name || "Cliente", customer_phone: po.orders?.users?.phone || "No disponible" })) || [] };
        }));
        res.json(formattedPackages);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/driver/packages/take", authMiddleware, driverMiddleware, async (req, res) => {
    const { package_id } = req.body;
    if (!package_id) return res.status(400).json({ error: "package_id requerido" });
    try {
        const { data: pkg, error: pkgError } = await supabase.from("dynamic_packages").select("*").eq("id", package_id).eq("status", "available").single();
        if (pkgError || !pkg) return res.status(404).json({ error: "Paquete no disponible" });
        const { data: packageOrders } = await supabase.from("package_orders").select("order_id").eq("package_id", package_id);
        if (packageOrders) for (const po of packageOrders) await supabase.from("orders").update({ driver_id: req.user.userId }).eq("id", po.order_id);
        const { data: updated, error: updateError } = await supabase.from("dynamic_packages").update({ status: "taken", taken_by: req.user.userId, taken_at: new Date().toISOString() }).eq("id", package_id).select().single();
        if (updateError) throw updateError;
        res.json({ message: "Paquete tomado", package: updated, total_orders: pkg.current_size });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/driver/packages/my", authMiddleware, driverMiddleware, async (req, res) => {
    try {
        const { data: packages, error } = await supabase.from("dynamic_packages").select("id, current_size, max_size, status, zone, delivery_date, delivery_window_start, delivery_window_end, taken_by, taken_at, created_at").eq("taken_by", req.user.userId).order("taken_at", { ascending: false });
        if (error) throw error;
        const formattedPackages = await Promise.all(packages.map(async (pkg) => {
            const { data: pkgOrders } = await supabase.from("package_orders").select("order_id, orders(id, user_id, delivery_address, delivery_latitude, delivery_longitude, total_amount, tip_amount, payment_method, created_at, zone, delivery_window_start, delivery_window_end, delivery_window_date, users!orders_user_id_fkey(full_name, phone))").eq("package_id", pkg.id);
            return { ...pkg, orders: pkgOrders?.map(po => ({ order_id: po.orders?.id, user_id: po.orders?.user_id, delivery_address: po.orders?.delivery_address, delivery_latitude: po.orders?.delivery_latitude, delivery_longitude: po.orders?.delivery_longitude, total_amount: po.orders?.total_amount, tip_amount: po.orders?.tip_amount || 0, payment_method: po.orders?.payment_method, created_at: po.orders?.created_at, zone: po.orders?.zone, delivery_window_start: po.orders?.delivery_window_start, delivery_window_end: po.orders?.delivery_window_end, delivery_window_date: po.orders?.delivery_window_date, customer_name: po.orders?.users?.full_name || "Cliente", customer_phone: po.orders?.users?.phone || "No disponible" })) || [] };
        }));
        res.json(formattedPackages);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/driver/earnings/packages", authMiddleware, driverMiddleware, async (req, res) => {
    try {
        const today = new Date();
        const dayOfWeek = today.getDay();
        const daysToMonday = dayOfWeek === 0 ? 6 : dayOfWeek - 1;
        const weekStart = new Date(today);
        weekStart.setDate(today.getDate() - daysToMonday);
        weekStart.setHours(0, 0, 0, 0);
        const { data: deliveredOrders, error } = await supabase.from("orders").select("id, tip_amount, status, updated_at").eq("status", "completed").eq("driver_id", req.user.userId).gte("updated_at", weekStart.toISOString());
        if (error) throw error;
        let totalOrders = 0, totalBasePayment = 0, totalTips = 0;
        for (const order of deliveredOrders || []) { totalOrders++; totalBasePayment += 2.50; if (order.tip_amount) totalTips += parseFloat(order.tip_amount); }
        const platformCommission = totalBasePayment * 0.10;
        const driverNetAmount = totalBasePayment * 0.90 + totalTips;
        const daysUntilFriday = (5 - today.getDay() + 7) % 7;
        const nextFriday = new Date(today);
        nextFriday.setDate(today.getDate() + daysUntilFriday);
        res.json({ total_packages: deliveredOrders?.length || 0, total_orders: totalOrders, total_amount: totalBasePayment + totalTips, total_tips: totalTips, platform_commission: platformCommission, driver_net_amount: driverNetAmount, next_payment_date: nextFriday.toISOString().split("T")[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/driver/orders/:orderId/status", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("id, dynamic_package_id, driver_id, status, tip_amount").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (!order.dynamic_package_id) return res.status(400).json({ error: "Este pedido no esta asignado a ningun paquete" });
        const { data: pkg } = await supabase.from("dynamic_packages").select("id, taken_by").eq("id", order.dynamic_package_id).single();
        if (!pkg || pkg.taken_by !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido asignado" });
        const { data: updatedOrder, error: updateError } = await supabase.from("orders").update({ status, updated_at: new Date().toISOString() }).eq("id", orderId).select().single();
        if (updateError) return res.status(400).json({ error: "Error al actualizar" });
        await supabase.from("package_orders").delete().eq("order_id", orderId);
        const { data: remainingOrders } = await supabase.from("package_orders").select("order_id").eq("package_id", order.dynamic_package_id);
        if (remainingOrders && remainingOrders.length === 0) await supabase.from("dynamic_packages").update({ status: "completed", taken_by: null, taken_at: null }).eq("id", order.dynamic_package_id);
        res.json({ success: true, message: "Estado actualizado", order: updatedOrder });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/driver/orders/:orderId/start-trip", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("id, driver_id, status, user_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.driver_id !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido" });
        if (order.status === "in_progress") return res.json({ success: true, message: "Ya en camino" });
        const { data: updated, error: updateError } = await supabase.from("orders").update({ status: "in_progress", updated_at: new Date().toISOString() }).eq("id", orderId).select().single();
        if (updateError) throw updateError;
        const { data: customer } = await supabase.from("users").select("fcm_token, full_name").eq("id", order.user_id).single();
        if (customer?.fcm_token) await sendPushNotification(customer.fcm_token, "Tu pedido esta en camino", "Tu repartidor ya salio con tu pedido. Puedes seguirlo en tiempo real.");
        res.json({ success: true, order: updated });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ✅ FIX: Al cancelar, crea nuevo paquete disponible para que otros drivers lo puedan tomar
app.post("/driver/orders/:orderId/cancel", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data: order, error: orderError } = await supabase.from("orders")
            .select("id, driver_id, dynamic_package_id, status, zone, delivery_date, delivery_window_start, delivery_window_end")
            .eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.driver_id !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido" });

        // 1. Eliminar relacion package_orders
        await supabase.from("package_orders").delete().eq("order_id", orderId);

        // 2. Si el paquete viejo queda vacio, eliminarlo
        if (order.dynamic_package_id) {
            const { data: remaining } = await supabase.from("package_orders")
                .select("order_id").eq("package_id", order.dynamic_package_id);
            if (!remaining || remaining.length === 0) {
                await supabase.from("dynamic_packages").delete().eq("id", order.dynamic_package_id);
            }
        }

        // 3. Resetear el pedido sin paquete
        await supabase.from("orders").update({
            status: "pending",
            driver_id: null,
            dynamic_package_id: null,
            updated_at: new Date().toISOString()
        }).eq("id", orderId);

        // 4. Crear nuevo paquete disponible con este pedido
        const { data: newPkg, error: pkgError } = await supabase.from("dynamic_packages").insert({
            current_size: 1,
            max_size: 8,
            status: "available",
            zone: order.zone || "centro",
            delivery_date: order.delivery_date,
            delivery_window_start: order.delivery_window_start,
            delivery_window_end: order.delivery_window_end,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }).select().single();

        if (!pkgError && newPkg) {
            await supabase.from("package_orders").insert({ package_id: newPkg.id, order_id: orderId });
            await supabase.from("orders").update({ dynamic_package_id: newPkg.id }).eq("id", orderId);
            console.log(`✅ Pedido ${orderId} cancelado - nuevo paquete disponible: ${newPkg.id}`);
        } else {
            console.error(`❌ Error creando nuevo paquete:`, pkgError?.message);
        }

        res.json({ success: true, message: "Pedido cancelado y disponible de nuevo" });
    } catch (e) {
        console.error("❌ Error cancelando pedido:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.post("/driver/location", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId, latitude, longitude } = req.body;
    if (!orderId || latitude === undefined || longitude === undefined) { console.error('❌ driver/location: faltan campos', { orderId, latitude, longitude }); return res.status(400).json({ error: "orderId, latitude y longitude requeridos" }); }
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("driver_id").eq("id", orderId).single();
        if (orderError || !order) { console.error('❌ driver/location: pedido no encontrado', orderId); return res.status(404).json({ error: "Pedido no encontrado" }); }
        if (order.driver_id !== req.user.userId) { console.error('❌ driver/location: driver no coincide'); return res.status(403).json({ error: "No tienes este pedido" }); }
        const { error: upsertError } = await supabase.from("driver_locations").upsert({ driver_id: req.user.userId, order_id: orderId, latitude, longitude, updated_at: new Date().toISOString() }, { onConflict: "order_id" });
        if (upsertError) { console.error('❌ driver/location: error upsert', JSON.stringify(upsertError)); return res.status(500).json({ error: upsertError.message }); }
        console.log(`✅ driver/location guardado: ${orderId} ${latitude} ${longitude}`);
        res.json({ success: true });
    } catch (e) { console.error('❌ driver/location: excepcion', e.message); res.status(500).json({ error: e.message }); }
});

app.get("/driver/location/:orderId", authMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("user_id, driver_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId) return res.status(403).json({ error: "No autorizado" });
        const { data: location, error: locationError } = await supabase.from("driver_locations").select("latitude, longitude, updated_at").eq("order_id", orderId).single();
        if (locationError && locationError.code !== 'PGRST116') throw locationError;
        let driverInfo = { driver_name: null, driver_avatar: null };
        if (order.driver_id) {
            const { data: driver } = await supabase.from("users").select("full_name, avatar_url").eq("id", order.driver_id).single();
            if (driver) { driverInfo.driver_name = driver.full_name; driverInfo.driver_avatar = driver.avatar_url || null; }
        }
        res.json({ ...(location || {}), ...driverInfo });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/driver/location/by-driver/:driverId", authMiddleware, async (req, res) => {
    const { driverId } = req.params;
    try {
        const { data: location, error } = await supabase.from("driver_locations").select("latitude, longitude, updated_at").eq("driver_id", driverId).order("updated_at", { ascending: false }).limit(1).single();
        if (error && error.code === "PGRST116") return res.json({ latitude: null, longitude: null });
        if (error) throw error;
        res.json(location);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN - DASHBOARD ====================

app.get("/admin/dashboard/stats", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const today = new Date().toISOString().split("T")[0];
        const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString().split("T")[0];
        const { count: totalProducts } = await supabase.from("products").select("*", { count: "exact", head: true });
        const { data: products } = await supabase.from("products").select("stock, min_stock").gt("stock", 0);
        const lowStockProducts = products?.filter(p => p.stock < (p.min_stock || 0)).length || 0;
        const { count: outOfStockProducts } = await supabase.from("products").select("*", { count: "exact", head: true }).eq("stock", 0);
        const { data: todayOrders } = await supabase.from("orders").select("total_amount").eq("delivery_date", today).eq("status", "completed");
        const totalOrdersToday = todayOrders?.length || 0;
        const totalRevenueToday = todayOrders?.reduce((sum, o) => sum + parseFloat(o.total_amount || 0), 0) || 0;
        const { data: weekOrders } = await supabase.from("orders").select("total_amount").gte("delivery_date", weekAgo).eq("status", "completed");
        const totalOrdersWeek = weekOrders?.length || 0;
        const totalRevenueWeek = weekOrders?.reduce((sum, o) => sum + parseFloat(o.total_amount || 0), 0) || 0;
        const { count: totalDrivers } = await supabase.from("users").select("*", { count: "exact", head: true }).eq("user_type", "driver");
        const { data: activeDriversData } = await supabase.from("orders").select("driver_id").gte("updated_at", weekAgo).eq("status", "completed").not("driver_id", "is", null);
        const activeDrivers = new Set(activeDriversData?.map(o => o.driver_id) || []).size;
        const { data: pendingPaymentsData } = await supabase.from("driver_payments").select("net_amount").eq("payment_status", "pending");
        const pendingPayments = pendingPaymentsData?.reduce((sum, p) => sum + parseFloat(p.net_amount || 0), 0) || 0;
        const { count: pendingYappiApprovals } = await supabase.from("orders").select("*", { count: "exact", head: true }).in("status", ["waiting_confirmation", "pending_approval"]).eq("payment_method", "yappi");
        res.json({ totalProducts: totalProducts || 0, lowStockProducts, outOfStockProducts: outOfStockProducts || 0, totalOrdersToday, totalRevenueToday, totalOrdersWeek, totalRevenueWeek, totalDrivers: totalDrivers || 0, activeDrivers, pendingPayments, pendingYappiApprovals: pendingYappiApprovals || 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN - PRODUCTOS ====================

app.get("/admin/products", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        let query = supabase.from("products").select("*, categories(name)");
        if (req.query.category) query = query.eq("category_id", req.query.category);
        if (req.query.search) query = query.ilike("name", `%${req.query.search}%`);
        const { data, error } = await query;
        if (error) throw error;
        let products = data || [];
        if (req.query.low_stock === "true") products = products.filter(p => { const stock = p.stock || 0; const minStock = p.min_stock || 0; return stock > 0 && stock < minStock; });
        res.json(products.map(p => ({ ...p, category: p.categories?.name, stock: p.stock || 0, min_stock: p.min_stock || 0 })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/products", authMiddleware, adminMiddleware, async (req, res) => {
    const { name, description, price, unit, category_id, stock, min_stock, image_url } = req.body;
    try {
        const { data, error } = await supabase.from("products").insert({ name, description, price, unit, category_id, stock: stock || 0, min_stock: min_stock || 0, image_url, is_available: true }).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/admin/products/:id", authMiddleware, adminMiddleware, async (req, res) => {
    const updates = req.body;
    try {
        const { data, error } = await supabase.from("products").update(updates).eq("id", req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/admin/products/:id/stock", authMiddleware, adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { quantity, change_type, notes } = req.body;
    try {
        const { data: product, error: fetchError } = await supabase.from("products").select("stock").eq("id", id).single();
        if (fetchError) throw fetchError;
        const previousQuantity = product.stock || 0;
        let newQuantity = previousQuantity;
        if (change_type === "add") newQuantity = previousQuantity + quantity;
        else if (change_type === "subtract") newQuantity = Math.max(0, previousQuantity - quantity);
        else if (change_type === "set") newQuantity = quantity;
        const { error: updateError } = await supabase.from("products").update({ stock: newQuantity }).eq("id", id);
        if (updateError) throw updateError;
        await supabase.from("inventory_logs").insert({ product_id: id, previous_quantity: previousQuantity, new_quantity: newQuantity, change_type, notes, created_by: req.user.userId });
        res.json({ success: true, message: "Stock actualizado" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/admin/products/:id", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { error } = await supabase.from("products").delete().eq("id", req.params.id);
        if (error) throw error;
        res.json({ message: "Producto eliminado" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/products/upload-image", authMiddleware, adminMiddleware, async (req, res) => {
    const { imageBase64, mimeType } = req.body;
    if (!imageBase64) return res.status(400).json({ error: "imageBase64 es requerido" });
    try {
        const fileName = `product_${Date.now()}.jpg`;
        const fileBuffer = Buffer.from(imageBase64, 'base64');
        const contentType = mimeType || 'image/jpeg';
        const { error: uploadError } = await supabase.storage.from('product-images').upload(fileName, fileBuffer, { contentType, upsert: true });
        if (uploadError) { console.error('❌ Error subiendo imagen:', JSON.stringify(uploadError)); throw uploadError; }
        const { data: urlData } = supabase.storage.from('product-images').getPublicUrl(fileName);
        res.json({ success: true, image_url: urlData.publicUrl });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/drivers/payments", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        let query = supabase.from("driver_payments").select("*, users!driver_payments_driver_id_fkey(full_name)");
        if (req.query.status) query = query.eq("payment_status", req.query.status);
        if (req.query.driver_id) query = query.eq("driver_id", req.query.driver_id);
        const { data, error } = await query.order("week_start", { ascending: false });
        if (error) throw error;
        res.json(data.map(p => ({ ...p, driver_name: p.users?.full_name })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/drivers/payments/process", authMiddleware, adminMiddleware, async (req, res) => {
    const { payment_id, payment_status } = req.body;
    try {
        const { error } = await supabase.from("driver_payments").update({ payment_status, paid_at: payment_status === "paid" ? new Date().toISOString() : null }).eq("id", payment_id);
        if (error) throw error;
        res.json({ message: "Pago procesado" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/drivers/payments/calculate", authMiddleware, adminMiddleware, async (req, res) => {
    const { driver_id, week_start } = req.body;
    if (!driver_id || !week_start) return res.status(400).json({ error: "driver_id y week_start son requeridos" });
    try {
        const weekEnd = new Date(week_start);
        weekEnd.setDate(weekEnd.getDate() + 6);
        const { data: orders, error: ordersError } = await supabase.from("orders").select("id, tip_amount, total_amount").eq("driver_id", driver_id).eq("status", "completed").gte("updated_at", week_start).lte("updated_at", weekEnd.toISOString());
        if (ordersError) throw ordersError;
        const totalOrders = orders?.length || 0;
        const totalBasePayment = totalOrders * 2.50;
        const totalTips = orders?.reduce((sum, o) => sum + parseFloat(o.tip_amount || 0), 0) || 0;
        const platformCommission = totalBasePayment * 0.10;
        const netAmount = totalBasePayment * 0.90 + totalTips;
        const { data: payment, error: upsertError } = await supabase.from("driver_payments").upsert({ driver_id, week_start, week_end: weekEnd.toISOString().split("T")[0], total_orders: totalOrders, total_base_payment: totalBasePayment, total_tips: totalTips, platform_commission: platformCommission, net_amount: netAmount, payment_status: "pending" }, { onConflict: "driver_id,week_start" }).select().single();
        if (upsertError) throw upsertError;
        res.json({ success: true, payment, total_orders: totalOrders, net_amount: netAmount });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/inventory/logs", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        let query = supabase.from("inventory_logs").select("*, products(name), users!inventory_logs_created_by_fkey(full_name)").order("created_at", { ascending: false });
        if (req.query.product_id) query = query.eq("product_id", req.query.product_id);
        if (req.query.limit) query = query.limit(parseInt(req.query.limit));
        const { data, error } = await query;
        if (error) throw error;
        res.json(data.map(l => ({ ...l, product_name: l.products?.name, created_by_name: l.users?.full_name })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/categories", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("categories").select("*").order("name");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/drivers/list", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("id, full_name, email, phone, user_type").eq("user_type", "driver");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== STRIPE ====================

app.post('/payments/create-intent', authMiddleware, async (req, res) => {
    try {
        const { amount, currency = 'usd' } = req.body;
        if (!amount || amount <= 0) return res.status(400).json({ error: 'Monto invalido' });
        const paymentIntent = await stripe.paymentIntents.create({ amount, currency, metadata: { userId: req.user.userId } });
        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) { console.error('❌ Stripe error:', error.message); res.status(500).json({ error: error.message }); }
});

// ==================== ADMIN - PEDIDOS PENDIENTES ====================

app.get("/admin/orders/pending", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("orders").select("id, total_amount, tip_amount, delivery_address, delivery_date, delivery_window_start, delivery_window_end, delivery_window_date, status, zone, created_at, payment_method, dynamic_package_id, driver_id, users!orders_user_id_fkey(full_name, phone), order_items(quantity, unit_price, products(name, unit))").in("status", ["pending", "confirmed", "in_progress"]).eq("payment_status", "completed").order("delivery_window_date", { ascending: true }).order("delivery_window_start", { ascending: true });
        if (error) throw error;
        res.json(data.map(o => ({ id: o.id, total_amount: parseFloat(o.total_amount), tip_amount: parseFloat(o.tip_amount || 0), delivery_address: o.delivery_address, delivery_date: o.delivery_date, delivery_window_start: o.delivery_window_start, delivery_window_end: o.delivery_window_end, delivery_window_date: o.delivery_window_date, status: o.status, zone: o.zone, created_at: o.created_at, payment_method: o.payment_method, is_assigned: !!o.dynamic_package_id, driver_id: o.driver_id || null, customer_name: o.users?.full_name || "Cliente", customer_phone: o.users?.phone || "", items: (o.order_items || []).map(i => ({ name: i.products?.name || "Producto", unit: i.products?.unit || "", quantity: i.quantity, subtotal: i.unit_price * i.quantity })) })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== BANNERS ====================

app.get("/banners", async (req, res) => {
    try {
        const { data, error } = await supabase.from("banners").select("id, slot, title, image_url, is_active, price, product_id, link_url").eq("is_active", true).order("slot");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/banners", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("banners").select("*").order("slot");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch("/admin/banners/:id", authMiddleware, adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { imageBase64, mimeType, title, is_active, price, product_id, link_url } = req.body;
    try {
        let imageUrl = null;
        if (imageBase64) {
            const fileName = `banner_${id}_${Date.now()}.jpg`;
            const fileBuffer = Buffer.from(imageBase64, 'base64');
            const contentType = mimeType || 'image/jpeg';
            const { error: uploadError } = await supabase.storage.from('product-images').upload(fileName, fileBuffer, { contentType, upsert: true });
            if (uploadError) throw uploadError;
            const { data: urlData } = supabase.storage.from('product-images').getPublicUrl(fileName);
            imageUrl = urlData.publicUrl;
        }
        const updates = { updated_at: new Date().toISOString() };
        if (imageUrl) updates.image_url = imageUrl;
        if (title !== undefined) updates.title = title;
        if (is_active !== undefined) updates.is_active = is_active;
        if (price !== undefined) updates.price = price ? parseFloat(price) : null;
        if (product_id !== undefined) updates.product_id = product_id ? parseInt(product_id) : null;
        if (link_url !== undefined) updates.link_url = link_url;
        const { data, error } = await supabase.from("banners").update(updates).eq("id", id).select().single();
        if (error) throw error;
        res.json({ success: true, banner: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DEBUG ====================

app.get("/debug/users", async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("id, email, full_name, role, user_type");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== START ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   🌱 AGROAPP BACKEND v2.0             ║
╠════════════════════════════════════════╣
║   ✅ Puerto: ${PORT}                      ║
║   🗺️  Zonas David: Norte/Centro/Sur    ║
║   ⏰ Corte: 12pm y 6pm automatico     ║
║   📦 Bloques: max 8 pedidos/zona      ║
║   💳 Stripe: LIVE                      ║
║   📱 YAPPI: CONFIGURADO                ║
║   🔔 FCM: NOTIFICACIONES ACTIVAS      ║
║   🖼️  Banners: CONFIGURADOS            ║
╚════════════════════════════════════════╝
    `);
});
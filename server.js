const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
require("dotenv").config();

const app = express();

app.use((req, res, next) => {
    console.log(`📍 [${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

app.use(cors());
app.use(helmet());
app.use(express.json());

app.get("/", (req, res) => {
    res.json({ message: "🌱 API de AgroApp funcionando correctamente", version: "1.0.0", status: "online" });
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

const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: "Token invalido" });
    }
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

// ==================== AUTH ====================

app.post("/auth/register", async (req, res) => {
    const { full_name: name, email, password, phone, address, user_type } = req.body;
    if (!name || !email || !password || !address) return res.status(400).json({ error: "Faltan campos" });
    const userType = user_type === "driver" ? "driver" : "cliente";
    try {
        const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
        if (existing) return res.status(400).json({ error: "Email ya registrado" });
        const hashed = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert({ full_name: name, email, password_hash: hashed, phone, address, role: "cliente", user_type: userType }).select().single();
        if (error) throw error;
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
        const token = jwt.sign(
            { userId: user.id, role: user.role, userType: user.user_type || "cliente", name: user.full_name, address: user.address },
            JWT_SECRET, { expiresIn: "7d" }
        );
        res.json({ token, userId: user.id, name: user.full_name, role: user.role, address: user.address, user_type: user.user_type || "cliente" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/auth/profile", authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("id, full_name, email, phone, address, role, user_type").eq("id", req.user.userId).single();
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
    if (newPassword.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
    try {
        const { data: user, error } = await supabase.from("users").select("*").eq("id", req.user.userId).single();
        if (error || !user) return res.status(404).json({ error: "Usuario no encontrado" });
        const valid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!valid) return res.status(401).json({ error: "Contraseña actual incorrecta" });
        const hashed = await bcrypt.hash(newPassword, 10);
        const { error: updateError } = await supabase.from("users").update({ password_hash: hashed }).eq("id", req.user.userId);
        if (updateError) throw updateError;
        res.json({ message: "Contraseña actualizada correctamente" });
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
    const finalTipAmount = tip_amount || 0;
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
    const tomorrow = new Date(Date.now() + 86400000);
    const deliveryDate = tomorrow.toISOString().split("T")[0];
    let totalAmount = 0;
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product } = await supabase.from("products").select("price").eq("id", productId).single();
        if (product) totalAmount += product.price * item.quantity;
    }
    try {
        const { data: order, error: orderError } = await supabase.from("orders").insert({
            user_id: req.user.userId, payment_method: finalPaymentMethod, payment_status: "completed",
            delivery_address: finalDeliveryAddress || req.user.address, delivery_latitude: finalLatitude,
            delivery_longitude: finalLongitude, delivery_date: deliveryDate, total_amount: totalAmount,
            tip_amount: finalTipAmount, notes: notes || null, status: "pending"
        }).select().single();
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
        res.json({ message: "Pedido creado", orderId: order.id, deliveryDate });
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
        if (order.status !== "pending") return res.status(400).json({ error: "Solo se pueden cancelar pedidos pendientes" });
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
    const { items, deliveryAddress, delivery_address, delivery_latitude, delivery_longitude } = req.body;
    const finalDeliveryAddress = deliveryAddress || delivery_address;
    if (!items || items.length === 0) return res.status(400).json({ error: "Carrito vacio" });
    for (const item of items) {
        const productId = item.productId || item.product_id;
        const { data: product } = await supabase.from("products").select("stock, name").eq("id", productId).single();
        if (!product) return res.status(400).json({ error: `Producto no encontrado: ID ${productId}` });
        if (product.stock < item.quantity) return res.status(400).json({ error: `Stock insuficiente` });
    }
    const referenceCode = generateReferenceCode();
    const tomorrow = new Date(Date.now() + 86400000);
    const deliveryDate = tomorrow.toISOString().split("T")[0];
    let totalAmount = 0;
    for (const item of items) {
        const { data: product } = await supabase.from("products").select("price").eq("id", item.productId || item.product_id).single();
        if (product) totalAmount += product.price * item.quantity;
    }
    try {
        const { data: order, error: orderError } = await supabase.from("orders").insert({
            user_id: req.user.userId,
            payment_method: "yappi",
            payment_status: "pending",
            delivery_address: finalDeliveryAddress || req.user.address,
            delivery_latitude: delivery_latitude || null,
            delivery_longitude: delivery_longitude || null,
            delivery_date: deliveryDate,
            total_amount: totalAmount,
            reference_code: referenceCode,
            status: "pending"
        }).select().single();
        if (orderError) throw orderError;
        const orderItems = items.map(item => ({
            order_id: order.id,
            product_id: item.productId || item.product_id,
            quantity: item.quantity,
            unit_price: item.price || 0
        }));
        const { error: itemsError } = await supabase.from("order_items").insert(orderItems);
        if (itemsError) throw itemsError;
        res.json({ orderId: order.id, referenceCode, totalAmount, deliveryDate });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/orders/:id/confirm-yappi", authMiddleware, async (req, res) => {
    const { referenceCode } = req.body;
    try {
        const { data: order, error } = await supabase.from("orders").select("*").eq("id", req.params.id).single();
        if (error || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId) return res.status(403).json({ error: "No autorizado" });
        if (order.reference_code !== referenceCode) return res.status(400).json({ error: "Código de referencia incorrecto" });
        if (order.payment_status === "pending_approval" || order.payment_status === "completed") return res.json({ success: true, message: "Pedido ya enviado a revisión" });
        const { data: orderItems } = await supabase.from("order_items").select("product_id, quantity").eq("order_id", order.id);
        for (const item of orderItems || []) {
            const { data: product } = await supabase.from("products").select("stock").eq("id", item.product_id).single();
            await supabase.from("products").update({ stock: product.stock - item.quantity }).eq("id", item.product_id);
        }
        await supabase.from("orders").update({ payment_status: "pending_approval", status: "pending_approval", payment_confirmed_at: new Date().toISOString() }).eq("id", order.id);
        res.json({ success: true, message: "Pago enviado a revisión. El admin lo aprobará en breve.", orderId: order.id });
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
        const { data: packages, error } = await supabase.from("dynamic_packages").select("id, current_size, max_size, status, created_at, updated_at").eq("status", "available").order("created_at");
        if (error) throw error;
        const formattedPackages = await Promise.all(packages.map(async (pkg) => {
            const { data: pkgOrders } = await supabase.from("package_orders").select("order_id, orders(id, user_id, delivery_address, delivery_latitude, delivery_longitude, total_amount, tip_amount, payment_method, created_at, users!orders_user_id_fkey(full_name, phone))").eq("package_id", pkg.id);
            return { ...pkg, orders: pkgOrders?.map(po => ({ order_id: po.orders?.id, user_id: po.orders?.user_id, delivery_address: po.orders?.delivery_address, delivery_latitude: po.orders?.delivery_latitude, delivery_longitude: po.orders?.delivery_longitude, total_amount: po.orders?.total_amount, tip_amount: po.orders?.tip_amount || 0, payment_method: po.orders?.payment_method, created_at: po.orders?.created_at, customer_name: po.orders?.users?.full_name || "Cliente", customer_phone: po.orders?.users?.phone || "No disponible" })) || [] };
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
        const { data: packages, error } = await supabase.from("dynamic_packages").select("id, current_size, max_size, status, taken_by, taken_at, created_at").eq("taken_by", req.user.userId).order("taken_at", { ascending: false });
        if (error) throw error;
        const formattedPackages = await Promise.all(packages.map(async (pkg) => {
            const { data: pkgOrders } = await supabase.from("package_orders").select("order_id, orders(id, user_id, delivery_address, delivery_latitude, delivery_longitude, total_amount, tip_amount, payment_method, created_at, users!orders_user_id_fkey(full_name, phone))").eq("package_id", pkg.id);
            return { ...pkg, orders: pkgOrders?.map(po => ({ order_id: po.orders?.id, user_id: po.orders?.user_id, delivery_address: po.orders?.delivery_address, delivery_latitude: po.orders?.delivery_latitude, delivery_longitude: po.orders?.delivery_longitude, total_amount: po.orders?.total_amount, tip_amount: po.orders?.tip_amount || 0, payment_method: po.orders?.payment_method, created_at: po.orders?.created_at, customer_name: po.orders?.users?.full_name || "Cliente", customer_phone: po.orders?.users?.phone || "No disponible" })) || [] };
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
        for (const order of deliveredOrders || []) { totalOrders++; totalBasePayment += 2.50; if (order.tip_amount) totalTips += order.tip_amount; }
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
        if (!order.dynamic_package_id) return res.status(400).json({ error: "Este pedido no está asignado a ningún paquete" });
        const { data: pkg, error: pkgError } = await supabase.from("dynamic_packages").select("id, taken_by").eq("id", order.dynamic_package_id).single();
        if (pkgError || !pkg) return res.status(403).json({ error: "Paquete no encontrado" });
        if (pkg.taken_by !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido asignado" });
        const { data: updatedOrder, error: updateError } = await supabase.from("orders").update({ status, updated_at: new Date().toISOString() }).eq("id", orderId).select().single();
        if (updateError) return res.status(400).json({ error: "Error al actualizar" });
        await supabase.from("package_orders").delete().eq("order_id", orderId);
        const { data: remainingOrders } = await supabase.from("package_orders").select("order_id").eq("package_id", order.dynamic_package_id);
        if (remainingOrders && remainingOrders.length === 0) await supabase.from("dynamic_packages").update({ status: "completed", taken_by: null, taken_at: null }).eq("id", order.dynamic_package_id);
        res.json({ success: true, message: "Estado actualizado", order: updatedOrder });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DRIVER - INICIAR VIAJE ====================

app.post("/driver/orders/:orderId/start-trip", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("id, driver_id, status, user_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.driver_id !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido" });
        if (order.status === "in_progress") return res.json({ success: true, message: "Ya en camino" });
        const { data: updated, error: updateError } = await supabase.from("orders").update({ status: "in_progress", updated_at: new Date().toISOString() }).eq("id", orderId).select().single();
        if (updateError) throw updateError;
        console.log(`🚴 Driver ${req.user.userId} inició viaje para pedido ${orderId}`);
        res.json({ success: true, order: updated });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DRIVER - UBICACIÓN ====================

app.post("/driver/location", authMiddleware, driverMiddleware, async (req, res) => {
    const { orderId, latitude, longitude } = req.body;
    if (!orderId || latitude === undefined || longitude === undefined) return res.status(400).json({ error: "orderId, latitude y longitude requeridos" });
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("driver_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.driver_id !== req.user.userId) return res.status(403).json({ error: "No tienes este pedido" });
        await supabase.from("driver_locations").upsert({ driver_id: req.user.userId, order_id: orderId, latitude, longitude, updated_at: new Date().toISOString() }, { onConflict: "order_id" });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/driver/location/:orderId", authMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data: order, error: orderError } = await supabase.from("orders").select("user_id").eq("id", orderId).single();
        if (orderError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId) return res.status(403).json({ error: "No autorizado" });
        const { data: location, error: locationError } = await supabase.from("driver_locations").select("latitude, longitude, updated_at").eq("order_id", orderId).single();
        if (locationError && locationError.code !== 'PGRST116') throw locationError;
        res.json(location || {});
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
        const totalRevenueToday = todayOrders?.reduce((sum, o) => sum + (o.total_amount || 0), 0) || 0;
        const { data: weekOrders } = await supabase.from("orders").select("total_amount").gte("delivery_date", weekAgo).eq("status", "completed");
        const totalOrdersWeek = weekOrders?.length || 0;
        const totalRevenueWeek = weekOrders?.reduce((sum, o) => sum + (o.total_amount || 0), 0) || 0;
        const { count: totalDrivers } = await supabase.from("users").select("*", { count: "exact", head: true }).eq("user_type", "driver");
        const { data: activeDriversData } = await supabase.from("orders").select("driver_id").gte("updated_at", weekAgo).eq("status", "completed").not("driver_id", "is", null);
        const activeDrivers = new Set(activeDriversData?.map(o => o.driver_id) || []).size;
        const { data: pendingPaymentsData } = await supabase.from("driver_payments").select("net_amount").eq("payment_status", "pending");
        const pendingPayments = pendingPaymentsData?.reduce((sum, p) => sum + (p.net_amount || 0), 0) || 0;
        const { count: pendingYappiApprovals } = await supabase.from("orders").select("*", { count: "exact", head: true }).eq("payment_status", "pending_approval").eq("payment_method", "yappi");
        res.json({ totalProducts: totalProducts || 0, lowStockProducts, outOfStockProducts: outOfStockProducts || 0, totalOrdersToday, totalRevenueToday, totalOrdersWeek, totalRevenueWeek, totalDrivers: totalDrivers || 0, activeDrivers, pendingPayments, pendingYappiApprovals: pendingYappiApprovals || 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN - YAPPI PENDIENTES ====================

app.get("/admin/yappi/pending", authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("orders")
            .select("id, total_amount, reference_code, created_at, payment_confirmed_at, delivery_address, users!orders_user_id_fkey(full_name, phone, email)")
            .eq("payment_method", "yappi")
            .eq("payment_status", "pending_approval")
            .order("created_at", { ascending: false });
        if (error) throw error;
        res.json(data.map(o => ({
            id: o.id,
            total_amount: o.total_amount,
            reference_code: o.reference_code,
            created_at: o.created_at,
            payment_confirmed_at: o.payment_confirmed_at,
            delivery_address: o.delivery_address,
            customer_name: o.users?.full_name || "Cliente",
            customer_phone: o.users?.phone || "",
            customer_email: o.users?.email || ""
        })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/yappi/:orderId/approve", authMiddleware, adminMiddleware, async (req, res) => {
    const { orderId } = req.params;
    try {
        const { data, error } = await supabase
            .from("orders")
            .update({ payment_status: "completed", status: "confirmed", updated_at: new Date().toISOString() })
            .eq("id", orderId)
            .eq("payment_status", "pending_approval")
            .select().single();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "Pedido no encontrado o ya procesado" });
        console.log(`✅ Admin aprobó pago YAPPI del pedido ${orderId}`);
        res.json({ success: true, message: "Pago YAPPI aprobado", order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/yappi/:orderId/reject", authMiddleware, adminMiddleware, async (req, res) => {
    const { orderId } = req.params;
    const { reason } = req.body;
    try {
        const { data: orderItems } = await supabase.from("order_items").select("product_id, quantity").eq("order_id", orderId);
        for (const item of orderItems || []) {
            const { data: product } = await supabase.from("products").select("stock").eq("id", item.product_id).single();
            if (product) await supabase.from("products").update({ stock: product.stock + item.quantity }).eq("id", item.product_id);
        }
        const { data, error } = await supabase
            .from("orders")
            .update({ payment_status: "rejected", status: "cancelled", notes: reason ? `Pago rechazado: ${reason}` : "Pago YAPPI rechazado por admin", updated_at: new Date().toISOString() })
            .eq("id", orderId).select().single();
        if (error) throw error;
        console.log(`❌ Admin rechazó pago YAPPI del pedido ${orderId}`);
        res.json({ success: true, message: "Pago rechazado y stock devuelto", order: data });
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
        const totalTips = orders?.reduce((sum, o) => sum + (o.tip_amount || 0), 0) || 0;
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
        if (!amount || amount <= 0) return res.status(400).json({ error: 'Monto inválido' });
        const paymentIntent = await stripe.paymentIntents.create({ amount, currency, metadata: { userId: req.user.userId } });
        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) { res.status(500).json({ error: 'Error al procesar el pago' }); }
});

// ==================== DEBUG ====================

app.get("/debug/users", async (req, res) => {
    try {
        const { data, error } = await supabase.from("users").select("id, email, full_name, role, user_type, password_hash");
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== START ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   🌱 AGROAPP BACKEND - COMPLETO       ║
╠════════════════════════════════════════╣
║   ✅ Servidor corriendo en puerto ${PORT}  ║
║   💳 Stripe: CONFIGURADO               ║
║   💰 YAPPI: CONFIGURADO                ║
║   🚚 DRIVER: CONFIGURADO               ║
║   📦 PAQUETES: CONFIGURADO             ║
║   📍 TRACKING: CONFIGURADO             ║
║   👑 ADMIN: CONFIGURADO                ║
║   🏪 VENDEDOR: CONFIGURADO             ║
║   📊 STOCK AUTOMÁTICO: ✅              ║
║   💰 PAGOS DRIVERS: ✅                 ║
║   🗺️  START TRIP: ✅                   ║
║   📱 YAPPI APPROVAL: ✅                ║
╚════════════════════════════════════════╝
    `);
});
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // ✅ AGREGADO
require("dotenv").config();

const app = express();

// Middleware de logs
app.use((req, res, next) => {
    console.log(`📍 [${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Middlewares
app.use(cors());
app.use(helmet());
app.use(express.json());

// Ruta raíz
app.get("/", (req, res) => {
    res.json({
        message: "🌱 API de AgroApp funcionando correctamente",
        version: "1.0.0",
        status: "online",
        endpoints: {
            auth: {
                login: "POST /auth/login",
                register: "POST /auth/register",
                profile: "GET /auth/profile",
                updateProfile: "PATCH /auth/profile",
                changePassword: "PATCH /auth/password"
            },
            products: "GET /products",
            orders: {
                create: "POST /orders",
                myOrders: "GET /orders/my",
                cancel: "PATCH /orders/:id/cancel"
            },
            vendor: {
                byClient: "GET /vendor/orders/by-client",
                byProduct: "GET /vendor/orders/by-product",
                updateStatus: "PATCH /vendor/orders/:id/status"
            },
            payments: { // ✅ AGREGADO
                createIntent: "POST /payments/create-intent"
            }
        }
    });
});

// Health check
app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Inicializar Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
    console.error("❌ ERROR: Variables de entorno faltantes");
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);
console.log("✅ Supabase conectado");

// Middleware auth
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

// ==================== AUTH ====================

// Registro
app.post("/auth/register", async (req, res) => {
    console.log("📝 POST /auth/register");
    const { full_name: name, email, password, phone, address } = req.body;
    if (!name || !email || !password || !address)
        return res.status(400).json({ error: "Faltan campos" });
    try {
        const { data: existing } = await supabase
            .from("users").select("id").eq("email", email).single();
        if (existing) return res.status(400).json({ error: "Email ya registrado" });

        const hashed = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert({
            full_name: name, email, password_hash: hashed, phone, address, role: "cliente"
        }).select().single();
        if (error) throw error;
        console.log("✅ Usuario registrado:", data.id);
        res.json({ message: "Usuario creado", userId: data.id });
    } catch (e) {
        console.error("❌ Error en registro:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Login
app.post("/auth/login", async (req, res) => {
    console.log("🔐 POST /auth/login");
    const { email, password } = req.body;
    try {
        const { data: user, error } = await supabase
            .from("users").select("*").eq("email", email).single();
        if (error || !user) return res.status(401).json({ error: "Credenciales invalidas" });

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: "Credenciales invalidas" });

        const token = jwt.sign(
            { userId: user.id, role: user.role, name: user.full_name, address: user.address },
            JWT_SECRET, { expiresIn: "7d" }
        );
        console.log("✅ Login exitoso:", user.email);
        res.json({ token, userId: user.id, name: user.full_name, role: user.role, address: user.address });
    } catch (e) {
        console.error("❌ Error en login:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Obtener perfil
app.get("/auth/profile", authMiddleware, async (req, res) => {
    console.log("👤 GET /auth/profile");
    try {
        const { data, error } = await supabase
            .from("users").select("id, full_name, email, phone, address, role")
            .eq("id", req.user.userId).single();
        if (error) throw error;
        res.json(data);
    } catch (e) {
        console.error("❌ Error obteniendo perfil:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Editar perfil
app.patch("/auth/profile", authMiddleware, async (req, res) => {
    console.log("📝 PATCH /auth/profile");
    const { full_name, phone, address } = req.body;
    try {
        const { data, error } = await supabase
            .from("users")
            .update({ full_name, phone, address })
            .eq("id", req.user.userId)
            .select()
            .single();
        if (error) throw error;
        console.log("✅ Perfil actualizado:", data.id);
        res.json({
            message: "Perfil actualizado",
            name: data.full_name,
            phone: data.phone,
            address: data.address
        });
    } catch (e) {
        console.error("❌ Error actualizando perfil:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Cambiar contraseña
app.patch("/auth/password", authMiddleware, async (req, res) => {
    console.log("🔑 PATCH /auth/password");
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
        return res.status(400).json({ error: "Faltan campos" });
    if (newPassword.length < 6)
        return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
    try {
        const { data: user, error } = await supabase
            .from("users").select("*").eq("id", req.user.userId).single();
        if (error || !user) return res.status(404).json({ error: "Usuario no encontrado" });

        const valid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!valid) return res.status(401).json({ error: "Contraseña actual incorrecta" });

        const hashed = await bcrypt.hash(newPassword, 10);
        const { error: updateError } = await supabase
            .from("users").update({ password_hash: hashed }).eq("id", req.user.userId);
        if (updateError) throw updateError;

        console.log("✅ Contraseña actualizada:", user.email);
        res.json({ message: "Contraseña actualizada correctamente" });
    } catch (e) {
        console.error("❌ Error cambiando contraseña:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==================== PRODUCTOS ====================

app.get("/products", async (req, res) => {
    console.log("📦 GET /products");
    try {
        const { data, error } = await supabase
            .from("products")
            .select("*, categories(name)")
            .eq("is_available", true)
            .order("category_id");
        if (error) throw error;
        console.log(`✅ ${data.length} productos enviados`);
        res.json(data);
    } catch (e) {
        console.error("❌ Error en /products:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==================== PEDIDOS ====================

app.post("/orders", authMiddleware, async (req, res) => {
    console.log("📦 POST /orders");
    const { items, paymentMethod, deliveryAddress } = req.body;
    if (!items || items.length === 0)
        return res.status(400).json({ error: "Carrito vacio" });

    const now = new Date();
    const hour = now.getHours();
    if (hour < 8 || hour >= 12)
        return res.status(400).json({ error: "Solo se aceptan pedidos de 8am a 12pm" });

    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const deliveryDate = tomorrow.toISOString().split("T")[0];

    try {
        const { data: order, error: orderError } = await supabase
            .from("orders").insert({
                user_id: req.user.userId,
                payment_method: paymentMethod,
                delivery_address: deliveryAddress || req.user.address,
                delivery_date: deliveryDate,
                total_amount: 0
            }).select().single();
        if (orderError) throw orderError;

        const orderItems = items.map(item => ({
            order_id: order.id,
            product_id: item.productId,
            quantity: item.quantity,
            unit_price: item.price
        }));

        const { error: itemsError } = await supabase.from("order_items").insert(orderItems);
        if (itemsError) throw itemsError;

        console.log("✅ Pedido creado:", order.id);
        res.json({ message: "Pedido creado", orderId: order.id, deliveryDate });
    } catch (e) {
        console.error("❌ Error creando pedido:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get("/orders/my", authMiddleware, async (req, res) => {
    console.log("📋 GET /orders/my");
    try {
        const { data, error } = await supabase
            .from("orders")
            .select("*, order_items(*, products(name, unit))")
            .eq("user_id", req.user.userId)
            .order("created_at", { ascending: false });
        if (error) throw error;
        console.log(`✅ ${data.length} pedidos enviados`);
        res.json(data);
    } catch (e) {
        console.error("❌ Error obteniendo pedidos:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// Cancelar pedido
app.patch("/orders/:id/cancel", authMiddleware, async (req, res) => {
    console.log("❌ PATCH /orders/:id/cancel");
    try {
        const { data: order, error: fetchError } = await supabase
            .from("orders").select("*").eq("id", req.params.id).single();
        if (fetchError || !order) return res.status(404).json({ error: "Pedido no encontrado" });
        if (order.user_id !== req.user.userId)
            return res.status(403).json({ error: "No autorizado" });
        if (order.status !== "pending")
            return res.status(400).json({ error: "Solo se pueden cancelar pedidos pendientes" });

        const { data, error } = await supabase
            .from("orders").update({ status: "cancelled" })
            .eq("id", req.params.id).select().single();
        if (error) throw error;
        console.log("✅ Pedido cancelado:", data.id);
        res.json({ message: "Pedido cancelado", order: data });
    } catch (e) {
        console.error("❌ Error cancelando pedido:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==================== VENDEDOR ====================

app.get("/vendor/orders/by-client", authMiddleware, async (req, res) => {
    console.log("📊 GET /vendor/orders/by-client");
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    try {
        const { data, error } = await supabase
            .from("orders_by_client").select("*").eq("delivery_date", date);
        if (error) throw error;
        res.json(data);
    } catch (e) {
        console.error("❌ Error en by-client:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get("/vendor/orders/by-product", authMiddleware, async (req, res) => {
    console.log("📊 GET /vendor/orders/by-product");
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    try {
        const { data, error } = await supabase
            .from("orders_by_product").select("*").eq("delivery_date", date);
        if (error) throw error;
        res.json(data);
    } catch (e) {
        console.error("❌ Error en by-product:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.patch("/vendor/orders/:id/status", authMiddleware, async (req, res) => {
    console.log("📝 PATCH /vendor/orders/:id/status");
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const { status } = req.body;
    try {
        const { data, error } = await supabase
            .from("orders").update({ status }).eq("id", req.params.id).select().single();
        if (error) throw error;
        console.log("✅ Estado actualizado:", data.id);
        res.json(data);
    } catch (e) {
        console.error("❌ Error actualizando estado:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ==================== STRIPE PAYMENTS ==================== ✅ NUEVA SECCIÓN

// Ruta para crear Payment Intent de Stripe
app.post('/payments/create-intent', authMiddleware, async (req, res) => {
    console.log("💳 POST /payments/create-intent");
    try {
        const { amount, currency = 'usd' } = req.body;

        if (!amount || amount <= 0) {
            return res.status(400).json({ error: 'Monto inválido' });
        }

        // Crear PaymentIntent en Stripe (convertir a centavos)
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount * 100),
            currency: currency,
            metadata: {
                userId: req.user.userId
            }
        });

        console.log(`✅ PaymentIntent creado: ${paymentIntent.id}`);

        // Devolver client_secret al frontend
        res.json({
            clientSecret: paymentIntent.client_secret
        });

    } catch (error) {
        console.error('❌ Error creating payment intent:', error.message);
        res.status(500).json({ error: 'Error al procesar el pago' });
    }
});

// ==================== START ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   🌱 AGROAPP BACKEND - RENDER         ║
╠════════════════════════════════════════╣
║   ✅ Servidor corriendo                ║
║   📡 Puerto: ${PORT}                        ║
║   💳 Stripe: CONFIGURADO               ║
║   🚀 URL: https://agroapp-backend.onrender.com  ║
╚════════════════════════════════════════╝
    `);
});
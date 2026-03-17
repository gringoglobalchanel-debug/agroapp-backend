const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

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
        res.json({ message: "Usuario creado", userId: data.id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Login
app.post("/auth/login", async (req, res) => {
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
        res.json({ token, userId: user.id, name: user.full_name, role: user.role, address: user.address });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ==================== PRODUCTOS ====================

app.get("/products", async (req, res) => {
    const { data, error } = await supabase
        .from("products")
        .select("*, categories(name)")
        .eq("is_available", true)
        .order("category_id");
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// ==================== PEDIDOS ====================

app.post("/orders", authMiddleware, async (req, res) => {
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

        res.json({ message: "Pedido creado", orderId: order.id, deliveryDate });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get("/orders/my", authMiddleware, async (req, res) => {
    const { data, error } = await supabase
        .from("orders")
        .select("*, order_items(*, products(name, unit))")
        .eq("user_id", req.user.userId)
        .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// ==================== VENDEDOR ====================

app.get("/vendor/orders/by-client", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    const { data, error } = await supabase
        .from("orders_by_client")
        .select("*")
        .eq("delivery_date", date);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.get("/vendor/orders/by-product", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const date = req.query.date || new Date(Date.now() + 86400000).toISOString().split("T")[0];
    const { data, error } = await supabase
        .from("orders_by_product")
        .select("*")
        .eq("delivery_date", date);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.patch("/vendor/orders/:id/status", authMiddleware, async (req, res) => {
    if (req.user.role !== "vendedor") return res.status(403).json({ error: "No autorizado" });
    const { status } = req.body;
    const { data, error } = await supabase
        .from("orders").update({ status }).eq("id", req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// ==================== START ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Servidor corriendo en puerto ${PORT}`));


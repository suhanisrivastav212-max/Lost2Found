
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
require("dotenv").config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());




const path = require("path");
const fs = require("fs");

const uploadFolder = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadFolder)) {
    fs.mkdirSync(uploadFolder);
}

app.use("/uploads", express.static(uploadFolder));

const storage = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, uploadFolder);
    },
    filename: function (req, file, callback) {
        const extension = path.extname(file.originalname).toLowerCase();
        const uniqueName = Date.now() + "-" + Math.round(Math.random() * 1e9) + extension;
        callback(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, callback) {
        const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

        if (allowedTypes.includes(file.mimetype)) {
            callback(null, true);
        } else {
            callback(new Error("Only JPG, PNG, and WEBP images are allowed."));
        }
    }
});




 // Item database model
const itemSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    status: {
        type: String,
        enum: ["Lost", "Found"],
        required: true
    },
    location: {
        type: String,
        required: true,
        trim: true
    },
    image: {
        type: String,
        default: ""
    },
    category: {
        type: String,
        default: ""
    },
    dateLost: {
        type: String,
        default: ""
    },
    description: {
        type: String,
        default: ""
    },
    contactName: {
        type: String,
        default: ""
    },
    phone: {
        type: String,
        default: ""
    },
    email: {
        type: String,
        default: ""
    },

    owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
}


}, { timestamps: true });

const Item = mongoose.model("Item", itemSchema);

// Message database model
const messageSchema = new mongoose.Schema({
    itemId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Item",
        required: true
    },
    itemName: {
        type: String,
        required: true
    },
    senderName: {
        type: String,
        required: true,
        trim: true
    },
    message: {
        type: String,
        required: true,
        trim: true,
        maxlength: 1000
    },
    status: {
        type: String,
        default: "New"
    }
}, { timestamps: true });

const Message = mongoose.model("Message", messageSchema);

// User database model
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ["user", "admin"],
        default: "user"
    }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);


// JWT Authentication Middleware
async function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Access denied. Login required."
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = require("jsonwebtoken").verify(
            token,
            process.env.JWT_SECRET
        );

        // Check current user in database
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(401).json({
                message: "User not found."
            });
        }

        req.user = user;
        next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token."
        });
    }
}

// Admin Authorization Middleware
function adminOnly(req, res, next) {

    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Access denied. Admin only."
        });
    }

    next();
}


// User Signup API
app.post("/api/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name?.trim() || !email?.trim() || !password) {
            return res.status(400).json({
                message: "All fields are required."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters."
            });
        }

        const existingUser = await User.findOne({
            email: email.trim().toLowerCase()
        });

        if (existingUser) {
            return res.status(409).json({
                message: "Email already registered."
            });
        }

        const hashedPassword = await require("bcryptjs")
            .hash(password, 12);

        const newUser = await User.create({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            password: hashedPassword,
            role: "user"
        });

        res.status(201).json({
            message: "Account created successfully!",
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error("Signup error:", error.message);

        res.status(500).json({
            message: "Could not create account."
        });
    }
});

// User Login API
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email?.trim() || !password) {
            return res.status(400).json({
                message: "Email and password are required."
            });
        }

        // Find user
        const user = await User.findOne({
            email: email.trim().toLowerCase()
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Verify password
        const isMatch = await require("bcryptjs")
            .compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Create JWT token
        const token = require("jsonwebtoken").sign(
            {
                id: user._id,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({
            message: "Login successful!",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Login error:", error.message);

        res.status(500).json({
            message: "Login failed."
        });
    }
});


// Get Logged-in User Profile
app.get("/api/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select("-password");

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        res.json({
            message: "Profile fetched successfully!",
            user
        });

    } catch (error) {
        console.error("Profile error:", error.message);

        res.status(500).json({
            message: "Could not fetch profile."
        });
    }
});


// Update Logged-in User Profile
app.put("/api/profile", verifyToken, async (req, res) => {
    try {
        const { name, email } = req.body;

        if (!name?.trim() || !email?.trim()) {
            return res.status(400).json({
                message: "Name and email are required."
            });
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            {
                name: name.trim(),
                email: email.trim().toLowerCase()
            },
            {
                new: true,
                runValidators: true
            }
        ).select("-password");

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        res.json({
            message: "Profile updated successfully!",
            user
        });

    } catch (error) {
        console.error("Profile update error:", error.message);
        res.status(500).json({
            message: "Could not update profile."
        });
    }
});




// Home route
app.get("/", (req, res) => {
    res.send("Lost2Found Backend is Running!");
});

// Get all items from MongoDB
app.get("/api/items", async (req, res) => {
    try {
        const items = await Item.find()
    .select("-phone -email -contactName")
    .sort({ createdAt: -1 });

        res.json(items);
    } catch (error) {
        res.status(500).json({
            message: "Could not fetch items."
        });
    }
});


// Get logged-in user's items
app.get("/api/my-items", verifyToken, async (req, res) => {
    try {
        const items = await Item.find({
            owner: req.user._id
        })
        .select("-phone -email -contactName")
        .sort({ createdAt: -1 });

        res.json({
            totalItems: items.length,
            items
        });

    } catch (error) {
        console.error("My items error:", error.message);

        res.status(500).json({
            message: "Could not fetch your items."
        });
    }
});


// Edit logged-in user's item
app.put("/api/items/:id", verifyToken, async (req, res) => {
    try {
        const { name, status, location, category, dateLost, description } = req.body;

        const item = await Item.findOneAndUpdate(
            {
                _id: req.params.id,
                owner: req.user._id
            },
            {
                name,
                status,
                location,
                category,
                dateLost,
                description
            },
            {
                new: true,
                runValidators: true
            }
        );

        if (!item) {
            return res.status(404).json({
                message: "Item not found or access denied."
            });
        }

        res.json({
            message: "Item updated successfully!",
            item
        });

    } catch (error) {
        console.error("Edit item error:", error.message);

        res.status(500).json({
            message: "Could not update item."
        });
    }
});


// Delete logged-in user's item
app.delete("/api/items/:id", verifyToken, async (req, res) => {
    try {
        const item = await Item.findOneAndDelete({
            _id: req.params.id,
            owner: req.user._id
        });

        if (!item) {
            return res.status(404).json({
                message: "Item not found or access denied."
            });
        }

        res.json({
            message: "Item deleted successfully!"
        });

    } catch (error) {
        console.error("Delete item error:", error.message);

        res.status(500).json({
            message: "Could not delete item."
        });
    }
});


// Get single item by ID
app.get("/api/items/:id", async (req, res) => {
    try {
        const item = await Item.findById(req.params.id)
            .select("-phone -email -contactName");

        if (!item) {
            return res.status(404).json({
                message: "Item not found"
            });
        }

        res.json(item);

    } catch (error) {
        res.status(500).json({
            message: "Could not fetch item details"
        });
    }
});


// Find similar Lost/Found items
app.get("/api/items/:id/matches", async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);

        if (!item) {
            return res.status(404).json({
                message: "Item not found."
            });
        }

        const oppositeStatus =
            item.status === "Lost" ? "Found" : "Lost";

        const allItems = await Item.find({
    _id: { $ne: item._id },
    status: oppositeStatus
});

const matches = allItems.map(foundItem => {

    let score = 0;

    // Name matching
    if (
        foundItem.name.toLowerCase().includes(item.name.toLowerCase()) ||
        item.name.toLowerCase().includes(foundItem.name.toLowerCase())
    ) {
        score += 40;
    }

    // Category matching
    if (
        item.category &&
        foundItem.category &&
        item.category.toLowerCase() === foundItem.category.toLowerCase()
    ) {
        score += 30;
    }

    // Location matching
    if (
        item.location.toLowerCase() === foundItem.location.toLowerCase()
    ) {
        score += 20;
    }

    // Description matching
    if (
        item.description &&
        foundItem.description &&
        item.description.toLowerCase().includes(foundItem.description.toLowerCase())
    ) {
        score += 10;
    }

    return {
        ...foundItem.toObject(),
        matchScore: score
    };

}).filter(foundItem => foundItem.matchScore >= 30)
  .sort((a, b) => b.matchScore - a.matchScore);

        res.json(matches);

    } catch (error) {
        console.error("Matching error:", error.message);

        res.status(500).json({
            message: "Could not find matching items."
        });
    }
});


// Admin: Get all items
app.get("/api/admin/items", verifyToken, adminOnly, async (req, res) => {
    try {
        const items = await Item.find()
            .sort({ createdAt: -1 });

        res.json(items);

    } catch (error) {
        console.error("Admin items error:", error.message);

        res.status(500).json({
            message: "Could not fetch admin items."
        });
    }
});


// Get all registered users
app.get("/api/admin/users", verifyToken, adminOnly, async (req, res) => {
    try {
        const users = await User.find()
            .select("-password")
            .sort({ createdAt: -1 });

        res.json({
            totalUsers: users.length,
            users
        });

    } catch (error) {
        res.status(500).json({
            message: "Failed to fetch users."
        });
    }
});





// Test POST route
app.post("/api/test", (req, res) => {
    res.json({
        message: "POST route is working!"
    });
});


 // Add a new item to MongoDB
app.post("/api/items", verifyToken, upload.single("image"), async (req, res) => {

    try {
        const {
    name,
    status,
    location,
    category,
    dateLost,
    description,
    contactName,
    phone,
    email
} = req.body;

        if (
            !name?.trim() ||
            !["Lost", "Found"].includes(status) ||
            !location?.trim()
        ) {
            return res.status(400).json({
                message: "Valid name, status (Lost/Found), and location are required."
            });
        }

        const newItem = await Item.create({
            owner: req.user._id,
        name: name.trim(),
        status,
        location: location.trim(),
        image: req.file ? "/uploads/" + req.file.filename : "",

        category: category || "",
        dateLost: dateLost || "",
        description: description || "",
        contactName: contactName || "",
        phone: phone || "",
        email: email || ""
    });

        console.log("Saved item:", newItem);

        res.status(201).json({
            message: "Item added successfully!",
            item: newItem
        });
    } catch (error) {
        console.error("Save error:", error.message);
        res.status(500).json({
            message: "Could not save item."
        });
    }
});


// Save information message to MongoDB
app.post("/api/messages", async (req, res) => {
    try {
        console.log("Message route reached!");


        const { itemId, itemName, senderName, message } = req.body;

        if (
            !mongoose.isValidObjectId(itemId) ||
            !senderName?.trim() ||
            !message?.trim()
        ) {
            return res.status(400).json({
                message: "Valid item, name, and message are required."
            });
        }

        const item = await Item.findById(itemId);

        if (!item) {
            return res.status(404).json({
                message: "Item not found."
            });
        }

        const newMessage = await Message.create({
            itemId: item._id,
            itemName: item.name,
            senderName: senderName.trim(),
            message: message.trim()
        });

        console.log("Message saved:", newMessage._id);

        res.status(201).json({
            message: "Information sent successfully!",
            data: {
                itemName: newMessage.itemName,
                senderName: newMessage.senderName,
                message: newMessage.message,
                status: newMessage.status
            }
        });


    } catch (error) {
        console.error("Message save error:", error.message);
        res.status(500).json({
            message: "Could not save message."
        });
    }
});


    
 // Get saved information messages
app.get("/api/messages", async (req, res) => {
    try {
        const messages = await Message.find()
            .select("-senderName")
            .sort({ createdAt: -1 });

        res.json(messages);
    } catch (error) {
        console.error("Fetch messages error:", error.message);
        res.status(500).json({
            message: "Could not fetch messages."
        });
    }
});


// Mark a message as Read
app.patch("/api/messages/:id/read", async (req, res) => {
    try {
        const message = await Message.findByIdAndUpdate(
            req.params.id,
            { status: "Read" },
            { new: true }
        );

        if (!message) {
            return res.status(404).json({
                message: "Message not found."
            });
        }

        res.json({
            message: "Notification marked as Read!",
            data: message
        });

    } catch (error) {
        console.error("Update message error:", error.message);

        res.status(500).json({
            message: "Could not update notification."
        });
    }
});


// Admin: Get all messages
app.get("/api/admin/messages", verifyToken, adminOnly, async (req, res) => {
    try {
        const messages = await Message.find()
            .sort({ createdAt: -1 });

        res.json(messages);

    } catch (error) {
        console.error("Admin messages error:", error.message);

        res.status(500).json({
            message: "Could not fetch admin messages."
        });
    }
});



 // Connect MongoDB and start server
async function startServer() {
    try {
        if (!process.env.MONGO_URI) {
            throw new Error("MONGO_URI is missing from .env");
        }

        await mongoose.connect(process.env.MONGO_URI);
        console.log("MongoDB connected successfully!");

        app.listen(3000, () => {
            console.log("Server running at http://localhost:3000");
        });
    } catch (error) {
        console.error("Connection failed:", error.message);
    }
}

startServer();

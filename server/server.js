import express from "express";
import dotenv from "dotenv";
import config from "./config/config.js";
import connectDB from "./config/db.js";

//routes
import authRoutes from "./routes/auth.route.js";

dotenv.config();

const app = express();
const PORT = config.PORT;


app.get("/", (req, res) => {
    res.send("API is running...");
})
// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to the database
connectDB();

// routes
app.use("/api/v1/auth", authRoutes);


app.listen(PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
})
import express from "express";
import dotenv from "dotenv";
import config from "./config/config.js";
import connectDB from "./config/db.js";

dotenv.config();

const app = express();
const PORT = config.PORT;


app.get("/", (req, res) => {
    res.send("API is running...");
})

// Connect to the database
connectDB();

app.listen(PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
})
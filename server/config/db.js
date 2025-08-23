import mongoose from "mongoose";
import config from "./config.js";
const connectDB = async () => {
    try {
        const con = await mongoose.connect(config.DB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log(`Database connection successfully ${con.connection.host}`);
    } catch (err) {
        console.log(`Database connection failed: ${err.message}`);
        process.exit(1);
    }
}

export default connectDB;
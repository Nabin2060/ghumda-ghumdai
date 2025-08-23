import doenv from "dotenv";
doenv.config();

const config = {
    // server configuration
    NODE_ENV: process.env.NODE_ENV || "development",
    PORT: process.env.PORT || 7000,

    // database configuration
    DB_URI: process.env.DB_URI,

    //JWT Secret
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN,

    // hashing configuration
    SALT_ROUNDS: process.env.SALT_ROUNDS,
}

export default config;
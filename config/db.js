import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URL);
        console.log(`MongoDB connected successfully ${mongoose.connection.host}`);
    } catch (error) {
        console.log(`MongoDB Error - ${error}`);
    }
}

export default connectDB;
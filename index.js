// packages imports
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';

// files imports
import connectDB from './config/db.js';
import testRoutes from './routes/testRoutes.js';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/profileRoutes.js';
import jobRoutes from './routes/jobRoutes.js';
import employerRoutes from './routes/employerRoutes.js';
import jobseekerRoutes from './routes/jobSeekerRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import { errorMiddleware } from './middlewares/errorMiddleware.js';

//config
dotenv.config();

//DB Connection
connectDB();

//rest object
const app = express()

//middlewares

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files from the 'static' directory
app.use('/static/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/static/assets', express.static(path.join(__dirname, 'assets')));


app.use(express.json());
app.use(cors());
app.use(morgan('dev'));


//routes
app.use('/app/v1/test', testRoutes);
app.use('/app/v1/auth', authRoutes);
app.use('/app/v1/profile', userRoutes);
app.use('/app/v1/job', jobRoutes);
app.use('/app/v1/employer', employerRoutes);
app.use('/app/v1/jobSeeker', jobseekerRoutes);
app.use('/app/v1/admin', adminRoutes);

//Validation middleware
app.use(errorMiddleware)


app.get('/', (req, res) => {
    res.json({ message: "working" });
})

const port = process.env.PORT || 9000;
app.listen(port, () => {
    console.log(`Server is running on ${port}`);

})
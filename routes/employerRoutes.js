import express from 'express';
import { userAuth } from '../middlewares/authMiddleware.js';
import { createEmployerDetails, getEmployerDetails } from '../controllers/employerControllers.js';

const router = express.Router();


// DETAILS || POST
router.post('/employer-details', userAuth, createEmployerDetails);

// GET DETAILS || GET
router.post('/get-employer-details', userAuth, getEmployerDetails);

export default router;
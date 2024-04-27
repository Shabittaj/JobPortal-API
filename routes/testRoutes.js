import express from 'express';
import { testGetController, testPostController } from '../controllers/testControllers.js';
import { userAuth } from '../middlewares/authMiddleware.js';
const router = express.Router();

//Get Method
router.get('/test-Get', testGetController)

//Post Method
router.post('/test-post', userAuth, testPostController)

export default router;
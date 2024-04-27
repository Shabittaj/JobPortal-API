import express from 'express';
import { userAuth } from '../middlewares/authMiddleware.js';
import { addDetailsController, emailGetController, idGetController, updateDetailsControllers, updateUserController } from '../controllers/profileController.js';

const router = express.Router();

//GET WITH EMAIL || GET 
router.get('/email-details', userAuth, emailGetController);


//POST WITH EMAIL || POST 
router.post('/add-details', userAuth, addDetailsController);


//GET WITH ID || GET 
router.get('/details', userAuth, idGetController);

//UPDATE USER DETAILS || PUT 
router.patch('/update-user', userAuth, updateUserController)

//UPDATE EMPLOYER/JOBSEEKER DETAILS || PUT 
router.patch('/update-details', userAuth, updateDetailsControllers)

export default router;
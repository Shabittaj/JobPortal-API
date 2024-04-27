import jobModel from '../models/jobModel.js';
import jobSeekerModel from '../models/jobSeekerModel.js';
import employerModel from '../models/employerModel.js';
import applicationModel from '../models/applicationModel.js';
import userModel from '../models/userModel.js';

export const dashboard = async (req, res, next) => {
    try {
        if (req.user.role === 'admin') {
            const totalAdmins = await userModel.find({ role: 'admin' }).countDocuments();
            const totalJobs = await jobModel.countDocuments();
            const totalEmployers = await userModel.find({ role: 'employer' }).countDocuments();
            const totalJobSeekers = await userModel.find({ role: 'jobSeeker' }).countDocuments();
            const totalResumes = await jobSeekerModel.countDocuments({ resume: { $ne: null } }); // Count documents where resume is not null
            const totalApplications = await applicationModel.countDocuments();
            res.status(200).json({ totalAdmins, totalJobs, totalEmployers, totalJobSeekers, totalResumes, totalApplications });
        } else {
            next('only admin have the access to this route');
        }
    } catch (error) {
        next(error)
    }
}


export const registerAdmin = async (req, res, next) => {
    try {
        if (req.user.role === 'admin') {
            const user = await userModel.create(req.body);

            res.status(201).json({
                message: 'User registered successfully',
                status: true,
                user: {
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    location: user.location,
                    phoneNumber: user.phoneNumber,
                    role: user.role
                }
            })
        } else {
            next('only admin have the access to this route');
        }
    } catch (error) {
        next(error);
    }
}
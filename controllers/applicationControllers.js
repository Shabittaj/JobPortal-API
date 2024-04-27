import fs from 'fs'; // Import the Node.js 'fs' module
import mongoose from 'mongoose';
import applicationModel from '../models/applicationModel.js';
import jobSeekerModel from '../models/jobSeekerModel.js';
import jobModel from '../models/jobModel.js';
import path from 'path';


export const applyJobController = async (req, res, next) => {
    try {
        const jobId = req.params.id;
        console.log(jobId);
        // const { jobId } = req.body;
        const jobSeekerId = req.user.userId;
        const jobseekerRole = req.user.role;
        if (jobseekerRole === 'jobSeeker') {
            const jobSeeker = await jobSeekerModel.findOne({ userId: jobSeekerId });
            if (!jobSeeker) {
                next('jobSeeker not found');
            }

            const job = await jobModel.findById(jobId);
            if (!job) {
                next('job not found');
            }

            // Check if the job seeker has already applied to this job
            const existingApplication = await applicationModel.findOne({
                jobId: jobId,
                jobSeekerId: jobSeekerId
            });
            if (existingApplication) {
                // return next('You have already applied to this job');
                return res.status(400).json({ message: "You have already applied to this job" })
            }

            // Create a new application
            const applicationData = new applicationModel({
                jobId: jobId,
                jobSeekerId: jobSeekerId,
                status: 'applied', // Set initial status to 'applied'
                applicationDate: Date.now()
            });

            const application = await applicationData.save();

            res.status(201).json({ status: 'success', application });
        } else {
            next('you are not authorized to apply for job!');
        }
    } catch (error) {
        next(error);
    }

}


export const getAppliedData = async (req, res, next) => {
    try {
        const jobId = req.params.id;
        const applications = await applicationModel.find({ jobId });

        // Extract jobSeekerIds from applications
        const jobSeekerIds = applications.map(application => application.jobSeekerId);
        // console.log('ids', jobSeekerIds);

        let details = [];

        // Iterate over each jobSeekerId and fetch job seeker details
        for (let id of jobSeekerIds) {
            // Find job seeker details by id
            const jobSeekerDetails = await jobSeekerModel.findOne({ userId: id })
                .populate('userId', 'firstName lastName -password')
                .select(['education', 'resume', 'workHistory']).exec();

            // console.log('jobSeekerDetails', jobSeekerDetails); // Log jobSeekerDetails

            // Push job seeker details into the details array
            details.push(jobSeekerDetails);
        }

        // Send response with applications and job seeker details
        res.status(200).json({ applications, details });
    } catch (error) {
        console.error('Error fetching job seeker details:', error);
        next(error);
    }
}

// export const testgetAppliedData = async (req, res, next) => {
//     try {
//         // const { jobId } = req.query;
//         const { jobId } = req.body;
//         const employerId = req.user.userId;
//         const applications = await applicationModel.find({ jobId })
//         const jobSeekerIds = applications.map(application => application.jobSeekerId);
//         console.log(applications);
//         console.log(jobSeekerIds);
//         if (!applications) {
//             return next('no application found');
//         }
//         if (req.user.role === 'employer') {
//             const jobs = await jobModel.findById(jobId);
//             if (!jobs) {
//                 return next('no jobs found');
//             }
//             let details = []

//             for (let id in jobSeekerIds) {
//                 const objectId = new mongoose.Types.ObjectId(jobSeekerIds[id])
//                 const jobSeekerData = await jobSeekerModel.findById(objectId)
//                 // .select('resume')
//                 // .populate('userId', 'firstName lastName email -password');
//                 details = {
//                     jobSeekerData /*, jobs: {
//                         jobId: jobId,
//                         title: jobs.title
//                     }*/
//                 }

//                 // res.json({ status: true, details });
//                 // const applications = await applicationModel.find()
//                 //     .populate('jobSeekerId', 'resume')
//                 //     .populate('jobId', 'title description jobLocation') // Populate job details directly
//                 //     .select('status applicationDate'); // Select only necessary fields from the application

//             }
//             res.json({ status: true, details });
//         } else {
//             next('you are not authorized to access this details');
//         }
//     } catch (error) {
//         next(error);
//     }
// }

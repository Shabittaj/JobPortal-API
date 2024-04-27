import employerModel from "../models/employerModel.js";

export const createEmployerDetails = async (req, res, next) => {
    try {
        if (req.user.role === 'employer') {
            // Create a new Employer instance with data from the request body
            const newEmployer = new employerModel({
                userId: req.user.userId,
                companyName: req.body.companyName,
                companyDescription: req.body.companyDescription,
                numberOfEmployees: req.body.numberOfEmployees,
                companyWebsite: req.body.companyWebsite,
                industry: req.body.industry
            });

            const savedEmployer = await newEmployer.save();
            // const savedEmployer = await employerModel.create(req.body);

            res.status(201).json({
                message: 'Details registered successfully',
                status: true,
                savedEmployer
            });
        } else {
            next('You are not authorized');
        }
    } catch (error) {
        next(error);
    }
}

export const getEmployerDetails = async (req, res, next) => {
    try {
        if (req.user.role === 'employer') {
            const userId = req.user.userId;
            const employerDetails = await employerModel.findOne({ userId });

            if (employerDetails) {
                res.status(200).json(employerDetails);
            } else {
                res.status(404).json({ message: 'Employer details not found' });
            }
        } else {
            res.status(403).json({ message: 'You are not authorized' });
        }
    } catch (error) {
        next(error);
    }
}
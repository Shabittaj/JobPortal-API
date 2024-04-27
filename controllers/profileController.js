import userModel from "../models/userModel.js";
import employerModel from "../models/employerModel.js";
import jobSeekerModel from "../models/jobSeekerModel.js";


//DISPLAY PROFILE OF USER AND THEIR ROLE THROUGH ID
export const idGetController = async (req, res, next) => {
    try {
        const id = req.user.userId;
        const data = await userModel.findById({ _id: id });
        if (!data) {
            return res.status(401).json({ status: false, error: "User not found!" });
        }
        let details;
        const employerData = await employerModel.findOne({ userId: data._id });
        const jobSeekerData = await jobSeekerModel.findOne({ userId: data._id });
        if (employerData) {
            details = employerData;
        } else {
            details = jobSeekerData;
        }
        res.status(200).json({
            status: true,
            message: "Email found",
            data: data, details
        })


    } catch (error) {
        return res.status(400).json({
            message: 'Error in ID Get Controller',
            status: false,
            error: error
        })
    }
}

//DISPLAY PROFILE OF USER AND THEIR ROLE THROUGH EMAIL 
export const emailGetController = async (req, res) => {
    try {
        const email = req.user.email;
        const data = await userModel.findOne({ email: email });
        if (!data) {
            return res.status(401).json({ status: false, error: "User not found!" });
        } else {

            const extraData = await employerModel.findOne({ userId: data._id }) || await jobSeekerModel.findOne({ userId: data._id });
            res.status(200).json({
                status: true,
                message: "Email found",
                data: data, extraData
            })
        }

    } catch (error) {
        return res.status(400).json({
            message: 'Error in Email Get Controller',
            status: false,
            error: error
        })
    }

}

//UPDATE USER PROFILE 
export const updateUserController = async (req, res, next) => {
    const { firstName, lastName, email, phoneNumber, address } = req.body;
    try {
        const userId = req.user.userId;
        const user = await userModel.findById({ _id: userId });
        if (!user) {
            return next('User Not Found');
        }
        const updateField = req.body;

        // if (updateField.firstName) user.firstName = firstName;
        // if (updateField.lastName) user.lastName = lastName;
        // if (updateField.email) user.email = email;
        // if (updateField.phoneNumber) user.phoneNumber = phoneNumber;
        // if (updateField.address) user.address = address;

        // Update only the fields that are present in the request body
        for (const key in updateField) {
            if (Object.prototype.hasOwnProperty.call(updateField, key)) {
                user[key] = updateField[key];
            }
        }

        await user.save();

        const token = user.createJWT();
        res.status(201).json({
            status: true,
            message: 'User Updated Successfully',
            user,
            token

        })
    } catch (error) {
        next(error);
    }
}

//UPDATE DETAILS OF EMPLOYER/JOBSEEKER BASED ON USER ID
export const updateDetailsControllers = async (req, res, next) => {
    try {
        const id = req.user.userId;
        const data = await userModel.findById({ _id: id });
        if (!data) {
            return res.status(401).json({ status: false, error: "User not found!" });
        }

        let updatedDetails;  // Declare it once before the if statements

        const employerData = await employerModel.findOne({ userId: data._id });
        const jobSeekerData = await jobSeekerModel.findOne({ userId: data._id });

        if (employerData) {
            const updateFields = req.body;

            // Update only the fields that are present in the request body
            for (const key in updateFields) {
                if (Object.prototype.hasOwnProperty.call(updateField, key)) {
                    employerData[key] = updateFields[key];
                }
            }

            // Save the updated document
            updatedDetails = await employerData.save();
        }

        if (jobSeekerData) {

            const updateFields = req.body;

            if (updateFields.education) jobSeekerData.education = updateFields.education;
            if (updateFields.yearOfExperience) jobSeekerData.yearOfExperience = updateFields.yearOfExperience;
            if (updateFields.resume) jobSeekerData.resume = updateFields.resume;
            if (updateFields.portfolio) jobSeekerData.portfolio = updateFields.portfolio;
            if (updateFields.jobPreferences) jobSeekerData.jobPreferences = updateFields.jobPreferences;
            if (updateFields.workHistory) jobSeekerData.workHistory = updateFields.workHistory;
            if (updateFields.projects) jobSeekerData.projects = updateFields.projects;
            if (updateFields.certifications) jobSeekerData.certifications = updateFields.certifications;
            if (updateFields.skills) jobSeekerData.skills = updateFields.skills;
            if (updateFields.additionalInformation) jobSeekerData.additionalInformation = updateFields.additionalInformation;

            // Update only the fields that are present in the request body
            // for (const key in updateFields) {
            //     if (Object.prototype.hasOwnProperty.call(updateFields, key)) {
            //         jobSeekerData[key] = updateFields[key];
            //     }
            // }

            // Save the updated document
            updatedDetails = await jobSeekerData.save();
        }

        res.status(200).json({
            status: true,
            message: "Details Updated",
            data: data,

            updatedDetails: updatedDetails
        });

    } catch (error) {
        return res.status(400).json({
            message: 'Error in updating details',
            status: false,
            error: error
        });
    }
};


export const addDetailsController = async (req, res, next) => {
    try {
        const id = req.user.userId;
        const jobSeekerData = await jobSeekerModel.findOne({ userId: id });
        if (!jobSeekerData) {
            return res.status(401).json({ status: false, error: "Job seeker not found!" });
        }

        const { skills, experiences, certifications } = req.body;

        // Add the new skills to the existing ones
        if (skills && Array.isArray(skills)) {
            jobSeekerData.skills.push(...skills);
        }

        // Add the new experiences to the existing ones
        if (experiences && Array.isArray(experiences)) {
            jobSeekerData.experiences.push(...experiences);
        }

        // Add the new certifications to the existing ones
        if (certifications && Array.isArray(certifications)) {
            jobSeekerData.certifications.push(...certifications);
        }

        // Save the updated document
        await jobSeekerData.save();

        res.status(200).json({
            status: true,
            message: "Details added successfully",
            data: {
                skills: jobSeekerData.skills,
                experiences: jobSeekerData.experiences,
                certifications: jobSeekerData.certifications
            }
        });
    } catch (error) {
        return res.status(400).json({
            message: 'Error in adding details',
            status: false,
            error: error.message
        });
    }
};

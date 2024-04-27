import employerModel from "../models/employerModel.js";
import jobSeekerModel from "../models/jobSeekerModel.js";
import userModel from "../models/userModel.js";
import JWT from 'jsonwebtoken';

//GET ALL THE DETAILS 
export const authGetController = async (req, res) => {
    const user = await userModel.find();
    res.status(200).json({ details: user });
}

//DISPLAY PROFILE OF USER AND THEIR ROLE THROUGH EMAIL 
export const emailGetController = async (req, res) => {
    try {
        const data = await userModel.findOne({ email: req.params.email });
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

export const registerController = async (req, res, next) => {
    try {
        const { firstName, lastName, email, password, address, phoneNumber, role } = req.body;

        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists', status: false });
        }

        const newUser = new userModel({
            firstName,
            lastName,
            email,
            password,
            address,
            phoneNumber,
            role
        });

        // Generate OTP for email verification
        newUser.generateVerificationOTP();

        // Send email with verification OTP
        await newUser.sendVerificationEmail();

        // Save user details with email verification OTP
        await newUser.save();

        const token = newUser.createJWT();

        res.status(201).json({
            message: 'User registered successfully. Verification OTP sent to email.',
            status: true,
            user: {
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                email: newUser.email,
                address: newUser.address,
                phoneNumber: newUser.phoneNumber,
                role: newUser.role
            }, token
        });

    } catch (error) {
        next(error);
    }
};


// Endpoint to handle OTP verification
export const verifyEmailController = async (req, res, next) => {
    try {
        const email = req.user.email;
        const { otp } = req.body;

        // Find the user by email
        const user = await userModel.findOne({ email });

        // Check if user exists
        if (!user) {
            return res.status(404).json({ message: 'User not found', status: false });
        }

        user.isEmailVerified = await user.verifyEmailOTP(otp);

        // Verify the OTP
        if (user.isEmailVerified) {
            // Mark the email as verified
            try {
                // user.isEmailVerified = true;
                await user.save();
                const token = user.createJWT();
                return res.status(200).json({ message: 'Email verified successfully', status: true, token });
            } catch (error) {
                return next(error);
            }
        } else {
            console.log(user.isEmailVerified);
            return res.status(400).json({ message: 'Invalid OTP or OTP expired', status: false });
        }
    } catch (error) {
        next(error);
    }
};


export const loginPostController = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide required fields', status: false });
        }

        const user = await userModel.findOne({ email }).select("+password");
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password', status: false });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password', status: false });
        }

        const token = user.createJWT();

        // Check if user is verified
        if (!user.isEmailVerified) {
            // Send OTP again for email verification
            user.generateVerificationOTP();
            await user.sendVerificationEmail();
            await user.save();
            // return res.status(401).json({ message: 'Email is not verified. OTP sent again for verification', status: false });
        }

        user.password = undefined;
        res.status(200).json({
            message: 'User login successful',
            status: true,
            user,
            token
        });

    } catch (error) {
        next(error);
    }
};

export const deleteUser = async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'You are not authorized to delete this account.' });
        }
        const email = req.params.userEmail;
        let user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: `No user found with email ${email}` });
        }
        await userModel.deleteOne({ email });
        res.status(200).json({ message: 'User deleted successfully.' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
};
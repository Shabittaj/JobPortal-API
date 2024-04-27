import mongoose from 'mongoose';

const jobSchema = new mongoose.Schema({
    companyLogoUrl: {
        data: Buffer,
        contentType: {
            type: String,
        },
        filename: String,
        src: {
            type: String,
            default: "http://localhost:8000/static/assets/jobPortal.png", //default image for testing purposes
        }
    },
    title: {
        type: String,
        required: [true, 'Job title is require'],
        maxlength: 100
    },
    description: {
        type: String
    },
    preferredEducation: [{
        type: String
    }],
    preferredSkill: [{
        type: String
    }],
    jobType: {
        type: String,
        enum: ['full-time', 'part-time', 'internship', 'contract'],
        default: 'full-time'
    },
    jobLocation: {
        type: String,
        required: [true, 'Job Location is require']
    },
    createdBy: {
        type: mongoose.Types.ObjectId,
        ref: 'User'
    },
    status: {
        type: String,
        enum: ['active', 'inactive'],
        default: 'active'
    },
    industry: {
        type: String,
        default: 'others'
    },
    preferredExperience: {
        min: {
            type: Number,
            default: 0
        },
        max: {
            type: Number,
            default: 0
        }
    },
    salary: {
        min: {
            type: Number,
            default: 0
        },
        max: {
            type: Number,
            default: 0
        }
    }

}, { timestamps: true });


export default mongoose.model('Job', jobSchema);      
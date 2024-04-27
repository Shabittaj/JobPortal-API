import mongoose from 'mongoose';
const Schema = mongoose.Schema;

const jobSeekerSchema = new Schema({
    userId: {
        type: mongoose.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true
    },
    education: {
        type: String
    },
    yearOfExperience: {
        type: String
    },
    resume: {
        data: Buffer,
        contentType: {
            type: String,
            validate: {
                validator: function (value) {
                    const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/rtf', 'application/msword', 'text/rtf', 'application/doc', 'application/docx'];
                    return allowedTypes.includes(value);
                },
                message: 'Invalid file type for resume. Only PDF, text, and Word documents are allowed.',
            },
        },
        filename: String,
        src: String
    },
    portfolio: {
        type: String,
    },
    jobPreferences: [{
        desiredJobTitle: {
            type: String
        },
        desiredLocation: {
            type: String
        },
        desiredSalary: {
            type: Number
        },
    }],
    workHistory: [{
        jobTitle: {
            type: String
        },
        company: {
            type: String
        },
        startDate: {
            type: Date
        },
        endDate: {
            type: Date
        },
        responsibilities: {
            type: String
        },
    }],
    projects: [{
        projectName: {
            type: String
        },
        description: {
            type: String
        },
        technologiesUsed: [{
            type: String
        }],
        projectUrl: {
            type: String
        },
    }],
    certifications: [{
        certificationName: {
            type: String
        },
        issuingOrganization: {
            type: String
        },
        issuanceDate: {
            type: Date
        },
    }],
    skills: [{
        skillName: {
            type: String
        },
        proficiency: {
            type: String,
        },
    }],
    additionalInformation: {
        aboutMe: {
            type: String
        },
    },
}, { timestamps: true });

jobSeekerSchema.pre('save', async function () {
    try {
        if (!this.isModified) return;
    } catch (error) {
        next(error);
    }
})

export default mongoose.model('JobSeeker', jobSeekerSchema);

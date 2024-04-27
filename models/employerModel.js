import mongoose from 'mongoose'

const employerSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    companyName: {
        type: String,
        required: true
    },
    companyDescription: {
        type: String
    },
    companyWebsite: {
        type: String
    },
    industry: {
        type: String
    },
}, {
    timestamps: true
})

employerSchema.pre('save', async function () {
    try {
        if (!this.isModified) return;
    } catch (error) {
        next(error);
    }
})

export default mongoose.model('Employer', employerSchema)
import mongoose from 'mongoose';

const applicationSchema = new mongoose.Schema({
    jobId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job',
        required: true
    },
    jobSeekerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'JobSeeker',
        required: true
    },
    status: {
        type: String,
        enum: ['applied', 'pending', 'accepted', 'rejected'],
        default: 'pending'
    },
    applicationDate: {
        type: Date,
        default: Date.now
    }
});

export default mongoose.model('Application', applicationSchema);
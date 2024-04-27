import multer from 'multer';
import path from 'path';

// Multer configuration for handling file uploads to disk
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Set the destination folder
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

export const upload = multer({
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2MB file size limit
    },
});

const logoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'assets/'); // Set the destination folder
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

export const logoUpload = multer({
    storage: logoStorage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2MB file size limit
    },
});

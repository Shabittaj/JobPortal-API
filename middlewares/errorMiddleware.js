//error middleware 

export const errorMiddleware = (err, req, res, next) => {
    console.log(err);
    const defaultErrors = {
        statusCode: 500,
        message: err
    }

    //missing error
    if (err.name === "ValidationError") {
        defaultErrors.statusCode = 400;
        defaultErrors.message = Object.values(err.errors)
            .map((item) => item.message)
            .join(",");
    }

    //duplicate error
    if (err.code && err.code === 11000) {
        defaultErrors.statusCode = 400;
        defaultErrors.message = `${Object.keys(err.keyValue)} field already exists`;
    }

    res.status(defaultErrors.statusCode).json({ message: defaultErrors.message });
}
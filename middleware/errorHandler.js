const logger = require('../logger')
const { CustomError, ServerError } = require('../errors')

function errorHandler(err, req, res, next) {
    const logLevel = (err instanceof CustomError && err.status < 500) ? 'warn' : 'error';
    logger[logLevel]('Error caught by central handler:', {
        correlationId: req.correlationId || 'N/A',
        request: {
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
        },
        error: {
            message: err.message,
            name: err.name,
            status: err.status,
            stack: (err instanceof ServerError || !(err instanceof CustomError)) ? err.stack : undefined,
            cause: err.cause
        },
        userId: req.user?.id
    })
    let statusCode = 500
    let responseMessage = 'An internal server error occurred.'
    if (err instanceof CustomError) {
        statusCode = err.status || 500;
        responseMessage = err.message;
        if (err.name === 'ValidationError' && err.validationErrors) {
            if (res.headersSent) {
                return next(err)
            }
            const simplifiedErrors = err.validationErrors.map(e => ({
                field: e.path,
                message: e.msg
            }))
            return res.status(statusCode).json({ message: responseMessage, errors: simplifiedErrors });
        }
    }
    if (res.headersSent) {
        return next(err)
    }
    return res.status(statusCode).json({ message: responseMessage })
}

module.exports = errorHandler;
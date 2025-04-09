class CustomError extends Error {
    constructor(name, status, message, options){
        super(message, options)
        this.name = name
        this.status = status
    }
}

class AuthError extends CustomError {
    constructor(message, options){
        super('AuthenticationError', 401, message, options)
    }
}

class ServerError extends CustomError {
    constructor(message, options){
        super('ServerError', 500, message, options)
    }
}

class ValidationError extends CustomError {
    constructor(message, validationErrors, options){
        super('ValidationError',400, message, options)
        this.validationErrors  = validationErrors 
    }
}

class ConflictError extends CustomError {
    constructor(message, options){
        super('ConflictError', 409, message, options)
    }

}

class BadRequest extends CustomError {
    constructor(message, options){
        super('BadRequest', 400, message, options)
    }
}


module.exports = {
    CustomError,
    AuthError,
    ServerError,
    ValidationError,
    ConflictError,
    BadRequest,
}
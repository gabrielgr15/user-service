class CustomError extends Error {
    constructor(name, status, message){
        super(message)
        this.name = name
        this.status = status
    }
}

class AuthError extends CustomError {
    constructor(message){
        super('AuthenticationError', 401, message)
    }
}

class ServerError extends CustomError {
    constructor(message){
        super('ServerError', 500, message)
    }
}

class ValidationError extends CustomError {
    constructor(message, validationErrors ){
        super('ValidationError',400, message)
        this.validationErrors  = validationErrors 
    }
}

class ConflictError extends CustomError {
    constructor(message){
        super('ConflictError', 409, message)
    }

}

class BadRequest extends CustomError {
    constructor(message){
        super('BadRequest', 400, message)
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
const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');

const logsDirectory = path.join(__dirname, 'logs');
const fs = require('fs');
if (!fs.existsSync(logsDirectory)) {
    fs.mkdirSync(logsDirectory);
}

const fileRotateTransport = new winston.transports.DailyRotateFile({
    filename: path.join(logsDirectory, 'app-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '7d', 
    level: 'debug'
});

const consoleTransport = new winston.transports.Console({
    level: 'debug',
});

const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(        
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.printf((info) => {            
            let logMessage = `${info.timestamp} [${info.level.toUpperCase()}]: ${info.message}`;
            const splatData = info[Symbol.for('splat')];            
            if (splatData && splatData.length > 0) {                
                for (const item of splatData) {                    
                    if (typeof item === 'object' && item !== null) {                        
                        try {
                            logMessage += ` ${JSON.stringify(item)}`;
                        } catch (e) {
                            logMessage += ` [Unserializable Object]`;
                        }
                    } else if (item !== undefined) {                        
                        logMessage += ` ${item}`;
                    }                    
                }
            }          
            if (info.stack) {
                logMessage += `\n${info.stack}`;
            }            
            return logMessage;
        })
    ),
    transports: [
        fileRotateTransport,
        consoleTransport
    ]
});

module.exports = logger;
import type {IncomingMessage, ServerResponse} from "node:http";

export const node = () => {
    return {
        type: 'core',
        getHandler() {
            return function (req: IncomingMessage, res: ServerResponse) {
                console.log(req.url);
                res.statusCode = 200;
                res.end(JSON.stringify({
                    message: 'hola'
                }));
            }
        }
    };
};
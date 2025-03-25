import express from 'express';
import { decodeJwt } from 'jose';
import cors from 'cors';
import type { Request, Response, NextFunction } from 'express';

const app = express();
const router = express.Router();
const port = process.env.PORT || 9000;

app.use(cors());
app.use(express.json());

router.use(async (req: Request, res: Response, next: NextFunction) => {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
        return next({
            status: 401,
            statusText: 'Unauthorized',
            reason: 'No authorization header found.',
        });
    }

    const [type, token] = authorizationHeader?.split(' ');
    if (type !== 'Bearer') {
        return next({
            status: 401,
            statusText: 'Unauthorized',
            reason: 'Only bearer authentication is supported.',
        });
    }

    const decoded = decodeJwt(token);
    res.locals.jwt = decoded;
    next();
});
router.get('/:id', (req, res) => {
    const { id } = req.params;
    const { jwt } = res.locals;
    res.json({ resource: id, jwt });
});

router.use((error, req: Request, res: Response, next: NextFunction) => {
    if (error.status === 401) {
        res.status(401);
        res.statusMessage = error.statusText;
        res.send(error.reason);
    }
});

app.use('/api/resource', router);
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});

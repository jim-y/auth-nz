import express from 'express';
import session from 'express-session';
import type { Request, Response } from 'express';
import { createService } from 'auth-nz';

declare module 'express-session' {
    interface SessionData {
        user: {
            sub: string;
            email: string;
            password: string;
        }
    }
}

const app = express();
const port = process.env.PORT || 3002;

const users = [{
    sub: 'f55b8cf9-c29d-4ed7-8a83-1a76b719c748',
    email: 'test@example.com',
    password: 'Password1'
}];

const oidc = createService({
    basePath: 'http://localhost:3002',
    signInURL: new URL('http://localhost:3002/index.html'),
    consentURL: new URL('http://localhost:3002/consent.html'),
    errorURL: new URL('http://localhost:3002/error.html'),
    signingKey: 'cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2',
    showConsent() {
        return true
    },
    clients: [
        {
            client_id: 'foo',
            client_secret: 'bar',
            redirect_uris: ['http://localhost:3002/api/callback'],
            scope: 'openid offline_access email'
        }
    ],
    async getUser(req: Request) {
        if (req.session.user) {
            return req.session.user;
        }
        return null;
    }
});

app.use(express.static('public'));
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false
    }
}))
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const authRouter = express.Router();
authRouter.post('/login', (req: Request, res: Response) => {
    const { email, password, redirectTo } = req.body;
    const user = users.find(user => user.email === email && password === password);
    if (!user) {
        res.status(401).send('Wrong email or password');
        return;
    }
    req.session.user = user;
    res.redirect(redirectTo);
});
app.use('/api/auth', authRouter);

app.all('/api/oidc/*splat', oidc.handler);

app.get('/api/callback', async (req: Request, res: Response) => {
    const { code, error } = req.query;

    if (error != null && error !== '') {
        const errorUrl = new URL(`error.html`, `${req.protocol}://${req.host}`);
        Array.from(Object.entries(req.query)).forEach(([key, value]) => {
            errorUrl.searchParams.set(key, String(value));
        })
        res.redirect(errorUrl.href);
        return;
    }

    const protocol = req.protocol;
    const host = req.get('host');
    const resp = await fetch(new URL('/api/oidc/token', `${protocol}://${host}`), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: String(code),
            client_id: 'foo',
            client_secret: 'bar',
            redirect_uri: 'http://localhost:3002/api/callback'
        }).toString()
    });
    const { access_token } = await resp.json();

    const resourceResponse = await fetch('http://localhost:9000/api/resource/1', {
        headers: {
            Authorization: `Bearer ${access_token}`,
        }
    });
    const resource = await resourceResponse.json();
    res.json(resource);
});

app.listen(port, () => {
    console.log(`Express example server listening on port ${port}`);
})
import { cookies } from 'next/headers';

export const users = [
    {
        sub: '7313f',
        email: 'test@example.com',
        password: 'Password1',
        access_token: null
    }
];

export const sessions = [
    {
        id: '33c3d5e9-e619-43ae-ba99-d799622e55cf',
        user: users[0]
    }
];

export async function getSession(): Promise<{ sub: string; email: string; access_token?: string|null; } | null> {
    const cookieStore = await cookies()
    const cookie = cookieStore.get('__next:session__');
    if (cookie) {
        const session = sessions.find(session => session.id === cookie.value)
        if (session) {
            return session.user;
        }
    }
    return null;
}
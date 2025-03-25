'use client';

import { useSearchParams } from 'next/navigation';

export default function signInPage() {
    const searchParams = useSearchParams();
    const redirectTo = searchParams.get('redirectTo');
    return (
        <div style={{ display: 'flex' }}>

        <form action="/api/auth/login" method="POST" style={{ width: '300px', margin: '10% auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <h2 style={{ textAlign: 'center' }}>Sign In</h2>
            <input type="text" name="email" placeholder="Email" required autoFocus defaultValue="email@example.com" />
            <input type="password" name="password" placeholder="Password" required defaultValue="Password1" />
            <input type="hidden" name="redirectTo" value={String(redirectTo)} />
            <button type="submit">Sign In</button>
        </form>
        </div>
    );
}

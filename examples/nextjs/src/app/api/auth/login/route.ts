import { cookies } from 'next/headers'
import { sessions } from '@/lib/__store-mock__';

export async function POST(req: Request) {
    const cookieStore = await cookies()
    const formData = await req.formData()
    const name = formData.get('email')
    const email = formData.get('password')
    const redirectTo = formData.get('redirectTo')
    cookieStore.set('__next:session__', sessions[0].id, { secure: false, httpOnly: true, path: '/' });
    return Response.redirect(new URL(String(redirectTo)))
}
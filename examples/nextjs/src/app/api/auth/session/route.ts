import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/lib/__store-mock__';

export async function GET(req: NextRequest) {
    return NextResponse.json(await getSession());
}
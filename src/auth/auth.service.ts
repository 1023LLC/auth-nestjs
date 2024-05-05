import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    constructor() {}

    async signup() {
        return { message: 'Sign up was successful' }
    }


    async signin() {
        return ''
    }


    async signout() {
        return ''
    }
}

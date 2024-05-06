import { BadRequestException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import { PrismaService } from 'prisma/prisma.service';

import * as bcrypt from 'bcrypt';

import { JwtService } from '@nestjs/jwt';

import { jwtSecret } from 'src/utils/constants';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) {}

    async signup(dto:AuthDto) {
        const { email, password } = dto;

        const foundUser = await this.prisma.user.findUnique({where: {email}})

        if (foundUser){
            throw new BadRequestException('Email already exits!')
        }

        const hashedPassword = await this.hashPassword(password)

        await this.prisma.user.create({
            data: {
                email,
                hashedPassword
            }
        })

        return { message: 'Sign up was successful' }
    }


    async signin(dto: AuthDto) {
        const {email, password} = dto;

        const foundUser = await this.prisma.user.findUnique({ where: {email} })

        if (!foundUser) {
            throw new BadRequestException('Wrong credentials!')
        }

        const isMatch = await this.comparePasswords({ password, hash: foundUser.hashedPassword })

        if (!isMatch) {
            throw new BadRequestException('Wrong credentials!')
        }

        const token = await this.signToken({id: foundUser.id, email: foundUser.email})

        return { token }
    }


    async signout() {
        return ''
    }


    async hashPassword(password: string){
        const saltOrRounds = 10;

        return await bcrypt.hash(password, saltOrRounds);

    }

    async comparePasswords(args: {password:string, hash:string}){
        return await bcrypt.compare(args.password, args.hash);
    }


        // Sign jwt & return to the user


    async signToken(args: {id: string, email:string}) {
        const payload = args

        return this.jwt.signAsync(payload, {secret: jwtSecret})
    }
}

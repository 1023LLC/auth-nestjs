import { BadRequestException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import { PrismaService } from 'prisma/prisma.service';

import * as bcrypt from 'bcrypt';


@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

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

        return ''
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
}

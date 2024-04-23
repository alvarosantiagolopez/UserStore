import { JwtAdapter, bcryptAdapter } from "../../config";
import { UserModel } from "../../data";
import { CustomError, RegisterUserDto, UserEntity, LoginUserDto } from "../../domain";




export class AuthService {

    constructor() { }

    public async registerUser(registerUserDto: RegisterUserDto) {

        const existUser = await UserModel.findOne({ email: registerUserDto.email });
        if (existUser) throw CustomError.badRequest('Email already exists');

        try {

            const user = new UserModel(registerUserDto);

            user.password = bcryptAdapter.hash(registerUserDto.password);

            await user.save();

            const { password, ...userEntity } = UserEntity.fromObject(user);

            return {
                user: userEntity,
                token: 'ABC'
            };

        } catch (error) {
            throw CustomError.internalServer(`${error}`)
        }

    }

    public async loginUser(loginUserDto: LoginUserDto) {

        const user = await UserModel.findOne({ email: loginUserDto.email });
        if (!user) throw CustomError.badRequest('Email does not exist');

        const isMatching = bcryptAdapter.compare(loginUserDto.password, user.password);
        if (!isMatching) throw CustomError.badRequest(('Password is not valid'));

        const { password, ...userEntity } = UserEntity.fromObject(user);

        const token = await JwtAdapter.generateToken({ id: user.id, email: user.email });
        if (!token) throw CustomError.internalServer('Error whil creating JWT')

        return {
            user: userEntity,
            token: token,
        }

    }

}
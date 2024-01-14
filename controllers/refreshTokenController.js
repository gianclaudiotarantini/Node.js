const User = require('../model/User');
const jwt = require('jsonwebtoken');


const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;                                                // Estrazione dell'oggetto
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;                                   // Estrazione del valore del cookie

    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) return res.sendStatus(403); //Forbidden 
    // evaluate jwt 
    jwt.verify(                                                     // Verifica della validità 
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403);  // Se la verifica ha successo e il refreshToken è valido
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                { "UserInfo" : {
                    "username": decoded.username,
                    "roles" : roles
                }  },                       // Allora viene genarato un nuovo token
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            res.json({ accessToken })
        }
    );
}

module.exports = { handleRefreshToken }
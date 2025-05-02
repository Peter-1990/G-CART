import jwt from 'jsonwebtoken';
import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser()); // Middleware to parse cookies

// Login seller : /api/seller/login
export const sellerLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (password === process.env.SELLER_PASSWORD && email === process.env.SELLER_EMAIL) {
            const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '7d' });

            res.cookie('sellerToken', token, {
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production', 
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', 
                maxAge: 7 * 24 * 60 * 60 * 1000, 
            });

            return res.json({ success: true, message: "Logged In" });
        } else {
            return res.json({ success: false, message: "Invalid Credentials" });
        }
    } catch (error) {
        console.log(error.message);
        res.json({ success: false, message: error.message });
    }
}

// Seller isAuth auth : /api/seller/is-auth
export const isSellerAuth = async (req, res) => {
    try {
        const sellerToken = req.cookies.sellerToken;

        // Log the cookies for debugging
        console.log("Cookies:", req.cookies);
        console.log("Seller Token:", sellerToken);

        if (!sellerToken) {
            return res.status(401).json({ success: false, message: 'Not Authorized: No token provided' });
        }

        // Verify the token
        const tokenDecode = jwt.verify(sellerToken, process.env.JWT_SECRET);

        // Log the decoded token for debugging
        console.log("Decoded Token:", tokenDecode);

        // If token is valid, return success
        return res.status(200).json({ success: true, data: tokenDecode });
    } catch (error) {
        console.error("Token verification error:", error); // Log the error for debugging
        return res.status(401).json({ success: false, message: 'Not Authorized: Invalid token' });
    }
}

//logout seller: /api/seller/logout

export const sellerLogout = async (req, res) => {
    try {
        res.clearCookie('sellerToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });
        return res.json({ success: true, message: "Logged Out" });
    } catch (error) {
        console.log(error.message);
        res.json({ success: false, message: error.message });
    }
}
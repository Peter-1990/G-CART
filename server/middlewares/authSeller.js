import jwt from 'jsonwebtoken';

const authSeller = async (req, res, next) => {
    const { sellerToken } = req.cookies;

    // Log the token for debugging
    console.log("Seller Token:", sellerToken);

    if (!sellerToken) {
        return res.status(401).json({ success: false, message: 'Not Authorized: No token provided' });
    }

    try {
        // Verify the token
        const tokenDecode = jwt.verify(sellerToken, process.env.JWT_SECRET);
        
        // Log the decoded token for debugging
        console.log("Decoded Token:", tokenDecode);

        // Check if the email matches
        if (tokenDecode.email === process.env.SELLER_EMAIL) {
            next(); // Proceed to the next middleware or route handler
        } else {
            return res.status(403).json({ success: false, message: 'Not Authorized: Invalid seller' });
        }
    } catch (error) {
        console.error("Token verification error:", error); // Log the error for debugging
        return res.status(401).json({ success: false, message: 'Not Authorized: Invalid token' });
    }
}

export default authSeller;
export const testGetController = async (req, res) => {
    res.json({ message: "test for Get method is successful" });
}

export const testPostController = async (req, res) => {
    const { name } = req.body;
    res.status(200).json({ details: `Name is ${name}` });
}
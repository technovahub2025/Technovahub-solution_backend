import mongoose from "mongoose";

const SoftwareSolutionSchema = new mongoose.Schema({
    title:{type:String, required:true},
    description:{type:String, required:true}
})

const Software = mongoose.model("Software",SoftwareSolutionSchema )

export default Software;

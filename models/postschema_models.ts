const moongoose = require('mongoose');
const postschema = moongoose.Schema({
    title:{
        type: String,
        required: true,
        minLength: 3,
        trim: true,
    },
    description: {
        type: String,
        required: true,
        minLength: 10,
        trim: true,
    },
    userID:{
        type: moongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    }
},{
    timestamps: true,
})

export default moongoose.model('Post', postschema);
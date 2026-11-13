//Register JS
const departmentSelect = document.getElementById("department");
const courseSelect = document.getElementById("course");

const departmentCourses = {
    "Applied Science": [
        "B.Tech Artificial Intelligence (AI)",
        "B.Tech Computer Science Engineering (CSE)",
        "B.Tech Computer Science and Design (CSD)",
        "B.Tech Civil Engineering",
        "B.Tech Mechanical Engineering",
        "Diploma in Computer Science (CS)",
        "Diploma in Electronics and Communication Engineering (ECE)"
    ],

    "Allied Science": [
        "RMT",
        "OTT",
        "BPT"
    ],

    "Pharmacy": [
        "B.Pharma",
        "D.Pharma",
        "Pharm.D"
    ],

    "Computer Science": [
        "B.Tech Artificial Intelligence (AI)",
        "B.Tech Computer Science Engineering (CSE)",
        "B.Tech Computer Science and Design (CSD)",
        "Diploma in Computer Science (CS)"
    ],

    "Law": [
        "LLB"
    ],

    "Business Administration": [
        "BBA",
        "MBA"
    ],

    "Hotel Management": [
        "BHM (Bachelor of Hotel Management)",
        "B.Sc. Hospitality and Hotel Administration",
        "Diploma in Hotel Management",
        "Diploma in Food Production",
        "Diploma in Front Office Operations"
    ],

    "ME/CIVIL/ECE": [
        "B.Tech Mechanical Engineering",
        "B.Tech Civil Engineering",
        "Diploma in Electronics and Communication Engineering (ECE)"
    ],

    "Department of Computer Application": [
        "BCA",
        "MCA"
    ]
};

if (departmentSelect && courseSelect) {
    departmentSelect.addEventListener("change", function () {
        const selectedDepartment = this.value;

        // Clear the previous course options
        courseSelect.innerHTML = "";

        if (!selectedDepartment) {
            courseSelect.add(new Option("First select a department", ""));
            courseSelect.disabled = true;
            return;
        }

        // Add the default option
        courseSelect.add(new Option("Select your course", ""));

        // Add courses for the selected department
        const courses = departmentCourses[selectedDepartment] || [];

        courses.forEach(function (course) {
            courseSelect.add(new Option(course, course));
        });

        courseSelect.disabled = false;
    });
}
console.log("main.js!!");

const events = [
	{
		id: "a",
		start: "2022-02-02",
		end: "",
		title: "節分",
		description: "悪い鬼を追い払い福を招く",
		backgroundColor: "red",
		borderColor: "red",
		editable: true
	},
	{
		id: "b",
		start: "2022-02-03",
		end: "",
		title: "立春",
		description: "二十四節気の一つ",
		backgroundColor: "green",
		borderColor: "green",
		editable: true
	},
	{
		id: "c",
		start: "2022-02-08",
		end: "",
		title: "針供養",
		description: "古くなった針などを神社に納めて供養する",
		backgroundColor: "blue",
		borderColor: "blue",
		editable: true
	},
];

window.onload = (e)=>{

	// Calendar
	const elem = document.getElementById("my-calendar");
	const calendar = new FullCalendar.Calendar(elem, {
		initialView: "timeGridDay",
		initialDate: "2022-02-13",
		events: events,
		dateClick: (e)=>{
			console.log("dateClick:", e);
		},
		eventClick: (e)=>{
			console.log("eventClick:", e.event.title);
		},
		eventDidMount: (e)=>{
			tippy(e.el, {// Tippy
				content: e.event.extendedProps.description,
			});
		}
	});
	calendar.render();
}
fetch("/predict", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({
    weather: "rainy",
    road_conditions: "wet",
    time: 14,
    location: "SESSION ROAD",
    day_of_week: 1
  })
});


fetch("/location_stats")
  .then(res => res.json())
  .then(data => {
    console.log("Location Stats:", data);
    // You can display it in a table or chart
  });



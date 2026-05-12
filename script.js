const filterButtons = document.querySelectorAll("[data-filter]");
const workCards = document.querySelectorAll(".work-card");

filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const activeFilter = button.dataset.filter;

    filterButtons.forEach((item) => {
      item.classList.toggle("active", item === button);
    });

    workCards.forEach((card) => {
      const categories = card.dataset.category.split(" ");
      const shouldShow = activeFilter === "all" || categories.includes(activeFilter);
      card.hidden = !shouldShow;
    });
  });
});

package com.giftedlabs.eventoria.events.repository;

import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.criteria.Predicate;

public class EventSpecification {

    public static Specification<Event> withDynamicQuery(
            String name,
            String description,
            Category category,
            LocalDateTime startDateFrom,
            LocalDateTime startDateTo,
            EventStatus eventStatus,
            Boolean isTicketed,
            Boolean isFeatured,
            Long organizerId,
            String city,
            String state,
            Boolean isVirtual) {

        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (name != null && !name.isEmpty()) {
                predicates.add(criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("name")),
                        "%" + name.toLowerCase() + "%"));
            }

            if (description != null && !description.isEmpty()) {
                predicates.add(criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("description")),
                        "%" + description.toLowerCase() + "%"));
            }

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (startDateFrom != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(
                        root.get("startDate"), startDateFrom));
            }

            if (startDateTo != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(
                        root.get("startDate"), startDateTo));
            }

            if (eventStatus != null) {
                predicates.add(criteriaBuilder.equal(root.get("eventStatus"), eventStatus));
            }

            if (isTicketed != null) {
                predicates.add(criteriaBuilder.equal(root.get("isTicketed"), isTicketed));
            }

            if (isFeatured != null) {
                predicates.add(criteriaBuilder.equal(root.get("isFeatured"), isFeatured));
            }

            if (organizerId != null) {
                predicates.add(criteriaBuilder.equal(root.get("organizer").get("id"), organizerId));
            }

            if (city != null && !city.isEmpty()) {
                predicates.add(criteriaBuilder.equal(
                        criteriaBuilder.lower(root.get("venue").get("address").get("city")),
                        city.toLowerCase()));
            }

            if (state != null && !state.isEmpty()) {
                predicates.add(criteriaBuilder.equal(
                        criteriaBuilder.lower(root.get("venue").get("address").get("state")),
                        state.toLowerCase()));
            }

            if (isVirtual != null) {
                predicates.add(criteriaBuilder.equal(
                        root.get("venue").get("isVirtual"), isVirtual));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    public static Specification<Event> hasKeyword(String keyword) {
        return (root, query, criteriaBuilder) -> {
            if (keyword == null || keyword.isEmpty()) {
                return null;
            }

            String likePattern = "%" + keyword.toLowerCase() + "%";

            return criteriaBuilder.or(
                    criteriaBuilder.like(criteriaBuilder.lower(root.get("name")), likePattern),
                    criteriaBuilder.like(criteriaBuilder.lower(root.get("description")), likePattern),
                    criteriaBuilder.like(criteriaBuilder.lower(root.get("venue").get("name")), likePattern),
                    criteriaBuilder.like(criteriaBuilder.lower(root.get("venue").get("address").get("city")), likePattern)
            );
        };
    }

    public static Specification<Event> isPublished() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.equal(root.get("eventStatus"), EventStatus.PUBLISHED);
    }

    public static Specification<Event> isUpcoming() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.greaterThan(root.get("startDate"), LocalDateTime.now());
    }

    public static Specification<Event> hasCategoryIn(List<Category> categories) {
        return (root, query, criteriaBuilder) -> {
            if (categories == null || categories.isEmpty()) {
                return null;
            }
            return root.get("category").in(categories);
        };
    }

    public static Specification<Event> hasCapacityAvailable() {
        return (root, query, criteriaBuilder) -> {
            // This is a simplified version. For actual implementation, you might need a subquery
            // to check if the registrations count is less than the venue capacity
            return criteriaBuilder.isNotNull(root.get("venue").get("capacity"));
        };
    }
}
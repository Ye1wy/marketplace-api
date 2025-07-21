package repository

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type adsRepo struct {
	*baseRepo
}

func NewAdsRepo(db *pgxpool.Pool, logger *logger.Logger) *adsRepo {
	baseRepo := NewBaseRepo(db, logger)
	return &adsRepo{
		baseRepo: baseRepo,
	}
}

func (r *adsRepo) Create(ctx context.Context, ads domain.Ads) error {
	op := "reposiotry.adsRepository.Create"
	query := `INSERT INTO ads(title, description, price, image_url, author_id) 
			  VALUES (@title, @desc, @price, @image, @author_id)`
	args := pgx.NamedArgs{
		"title":     ads.Title,
		"desc":      ads.Description,
		"price":     ads.Price,
		"image":     ads.ImageURL,
		"author_id": ads.AuthorId,
	}

	r.logger.Debug("Check data", "author id", ads.AuthorId, "op", op)

	_, err := r.db.Exec(ctx, query, args)
	if err != nil {
		r.logger.Error("Exec error", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %v", op, err)
	}

	return nil
}

func (r *adsRepo) GetAll(ctx context.Context, filters domain.Filters) ([]domain.Ads, error) {
	op := "repository.adsRepository.GetAll"

	var sortField string

	switch filters.SortBy {
	case "price":
		sortField = "ads.price"
	default:
		sortField = "ads.created_at"
	}

	query := fmt.Sprintf(`
		SELECT 
			ads.id, ads.title, ads.description, ads.image_url, ads.price, ads.created_at,
			users.username,
			CASE WHEN ads.author_id = @author_id THEN true ELSE false END AS is_mine
		FROM ads
		JOIN users ON ads.author_id = users.id
		WHERE ads.price BETWEEN @minPrice AND @maxPrice
		ORDER BY %s %s
		LIMIT @pageSize OFFSET @offset
	`, sortField, filters.Order)

	args := pgx.NamedArgs{
		"author_id": filters.AuthorId,
		"minPrice":  filters.MinPrice,
		"maxPrice":  filters.MaxPrice,
		"pageSize":  filters.PageSize,
		"offset":    filters.Offset,
	}

	rows, err := r.db.Query(
		ctx,
		query,
		args,
	)
	if err != nil {
		r.logger.Error("Query error", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}
	defer rows.Close()

	var ads []domain.Ads

	for rows.Next() {
		var ad domain.Ads
		err := rows.Scan(
			&ad.Id,
			&ad.Title,
			&ad.Description,
			&ad.ImageURL,
			&ad.Price,
			&ad.CreatedAt,
			&ad.AuthorName,
			&ad.IsMine,
		)
		if err != nil {
			r.logger.Error("Failed to scan", logger.Err(err), "op", op)
			return nil, fmt.Errorf("%s: %v", op, err)
		}

		ads = append(ads, ad)
	}

	return ads, nil
}
